#!/usr/bin/env python3
"""Passkey (WebAuthn) ceremonies for the portal login.

Only what a passkey login needs is implemented: attestation "none", ES256,
RS256 and EdDSA credential keys, and the checks of the WebAuthn Level 2
verification procedures that apply to them. The module has no database or web
dependencies so the verification can be tested on its own; ``cryptography`` is
already a portal requirement.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


ALG_ES256 = -7
ALG_EDDSA = -8
ALG_RS256 = -257
SUPPORTED_ALGORITHMS = (ALG_ES256, ALG_EDDSA, ALG_RS256)

FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED_DATA = 0x40

MAX_CREDENTIAL_ID_BYTES = 1023


class WebAuthnError(ValueError):
    """A ceremony response that must not be accepted."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise WebAuthnError("Base64url-Wert erwartet")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise WebAuthnError("Ungueltiger Base64url-Wert") from exc


class _Cbor:
    """Decode the CBOR subset authenticators use: no floats, no indefinite lengths."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise WebAuthnError("CBOR-Daten sind abgeschnitten")
        chunk = self.data[self.offset:self.offset + length]
        self.offset += length
        return chunk

    def argument(self, info: int) -> int:
        if info < 24:
            return info
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if info not in sizes:
            raise WebAuthnError("Nicht unterstuetzte CBOR-Laenge")
        return int.from_bytes(self.take(sizes[info]), "big")

    def item(self, depth: int = 0) -> Any:
        if depth > 16:
            raise WebAuthnError("CBOR-Daten sind zu tief verschachtelt")
        initial = self.take(1)[0]
        major, info = initial >> 5, initial & 0x1F
        if major == 7:
            simple = {20: False, 21: True, 22: None}
            if info not in simple:
                raise WebAuthnError("Nicht unterstuetzter CBOR-Wert")
            return simple[info]
        value = self.argument(info)
        if major == 0:
            return value
        if major == 1:
            return -1 - value
        if major == 2:
            return self.take(value)
        if major == 3:
            try:
                return self.take(value).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise WebAuthnError("Ungueltiger CBOR-Text") from exc
        if major == 4:
            return [self.item(depth + 1) for _ in range(value)]
        if major == 5:
            result: dict[Any, Any] = {}
            for _ in range(value):
                key = self.item(depth + 1)
                if isinstance(key, (list, dict)):
                    raise WebAuthnError("Ungueltiger CBOR-Schluessel")
                result[key] = self.item(depth + 1)
            return result
        if major == 6:
            return self.item(depth + 1)
        raise WebAuthnError("Unbekannter CBOR-Typ")


def cbor_decode(data: bytes, *, allow_trailing: bool = False) -> tuple[Any, int]:
    """Decode one CBOR item and return it with the number of bytes it used."""
    decoder = _Cbor(data)
    value = decoder.item()
    if not allow_trailing and decoder.offset != len(data):
        raise WebAuthnError("Unerwartete Daten nach dem CBOR-Wert")
    return value, decoder.offset


def parse_authenticator_data(data: bytes) -> dict[str, Any]:
    if len(data) < 37:
        raise WebAuthnError("Authenticator-Daten sind zu kurz")
    flags = data[32]
    parsed: dict[str, Any] = {
        "rp_id_hash": data[:32],
        "flags": flags,
        "sign_count": struct.unpack(">I", data[33:37])[0],
    }
    if flags & FLAG_ATTESTED_DATA:
        if len(data) < 55:
            raise WebAuthnError("Attestierte Credential-Daten fehlen")
        parsed["aaguid"] = data[37:53]
        length = struct.unpack(">H", data[53:55])[0]
        if length > MAX_CREDENTIAL_ID_BYTES or 55 + length > len(data):
            raise WebAuthnError("Credential-ID ist ungueltig")
        parsed["credential_id"] = data[55:55 + length]
        key, used = cbor_decode(data[55 + length:], allow_trailing=True)
        if not isinstance(key, dict):
            raise WebAuthnError("Credential-Schluessel ist kein COSE-Schluessel")
        parsed["credential_key"] = key
        parsed["extensions_offset"] = 55 + length + used
    return parsed


def cose_public_key(key: dict[Any, Any]) -> tuple[int, Any]:
    """Turn a COSE key into its algorithm and a cryptography public key."""
    kty, alg = key.get(1), key.get(3)
    if alg == ALG_ES256 and kty == 2 and key.get(-1) == 1:
        x, y = key.get(-2), key.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise WebAuthnError("EC2-Schluessel ist unvollstaendig")
        return alg, ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    if alg == ALG_EDDSA and kty == 1 and key.get(-1) == 6:
        x = key.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise WebAuthnError("Ed25519-Schluessel ist unvollstaendig")
        return alg, ed25519.Ed25519PublicKey.from_public_bytes(x)
    if alg == ALG_RS256 and kty == 3:
        n, e = key.get(-1), key.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes)) or len(n) < 256:
            raise WebAuthnError("RSA-Schluessel ist unvollstaendig oder zu kurz")
        return alg, rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
    raise WebAuthnError("Schluesseltyp des Passkeys wird nicht unterstuetzt")


def public_key_der(public_key: Any) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_signature(algorithm: int, key_der: bytes, signature: bytes, signed: bytes) -> None:
    public_key = serialization.load_der_public_key(key_der)
    try:
        if algorithm == ALG_ES256 and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif algorithm == ALG_EDDSA and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signed)
        elif algorithm == ALG_RS256 and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise WebAuthnError("Algorithmus passt nicht zum gespeicherten Schluessel")
    except InvalidSignature as exc:
        raise WebAuthnError("Signatur des Passkeys ist ungueltig") from exc


def verify_client_data(raw: bytes, *, ceremony: str, challenge: bytes, origin: str) -> None:
    try:
        client = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebAuthnError("clientDataJSON ist ungueltig") from exc
    if not isinstance(client, dict) or client.get("type") != ceremony:
        raise WebAuthnError("Falscher Zeremonientyp")
    if not hmac.compare_digest(b64url_decode(str(client.get("challenge", ""))), challenge):
        raise WebAuthnError("Challenge stimmt nicht ueberein")
    if client.get("origin") != origin:
        raise WebAuthnError(f"Unerwarteter Ursprung {client.get('origin')!r}")
    if client.get("crossOrigin") is True:
        raise WebAuthnError("Eingebettete Anmeldung ist nicht erlaubt")


def verify_rp_and_flags(auth: dict[str, Any], rp_id: str) -> None:
    if not hmac.compare_digest(auth["rp_id_hash"], hashlib.sha256(rp_id.encode("utf-8")).digest()):
        raise WebAuthnError("Passkey gehoert zu einer anderen Domain")
    if not auth["flags"] & FLAG_USER_PRESENT:
        raise WebAuthnError("Benutzeranwesenheit wurde nicht bestaetigt")
    if not auth["flags"] & FLAG_USER_VERIFIED:
        raise WebAuthnError("Benutzerverifikation (PIN oder Biometrie) fehlt")


def verify_registration(
    *, client_data_json: bytes, attestation_object: bytes, challenge: bytes, origin: str, rp_id: str,
) -> dict[str, Any]:
    """Check a navigator.credentials.create() response and return the credential.

    The portal asks for attestation "none": it trusts the user who is logged in
    to choose the authenticator, so the attestation statement is not evaluated.
    """
    verify_client_data(client_data_json, ceremony="webauthn.create", challenge=challenge, origin=origin)
    attestation, _used = cbor_decode(attestation_object)
    if not isinstance(attestation, dict) or not isinstance(attestation.get("authData"), bytes):
        raise WebAuthnError("attestationObject ist ungueltig")
    auth = parse_authenticator_data(attestation["authData"])
    verify_rp_and_flags(auth, rp_id)
    if "credential_id" not in auth:
        raise WebAuthnError("Die Antwort enthaelt keinen neuen Passkey")
    algorithm, key = cose_public_key(auth["credential_key"])
    return {
        "credential_id": b64url_encode(auth["credential_id"]),
        "public_key": public_key_der(key),
        "algorithm": algorithm,
        "sign_count": auth["sign_count"],
        "aaguid": auth["aaguid"].hex(),
    }


def verify_authentication(
    *, client_data_json: bytes, authenticator_data: bytes, signature: bytes, challenge: bytes,
    origin: str, rp_id: str, public_key: bytes, algorithm: int, stored_sign_count: int,
) -> int:
    """Check a navigator.credentials.get() response and return the new sign count.

    A counter that does not grow although the authenticator keeps one points to
    a cloned key, so the login is refused. Synced passkeys always report 0.
    """
    verify_client_data(client_data_json, ceremony="webauthn.get", challenge=challenge, origin=origin)
    auth = parse_authenticator_data(authenticator_data)
    verify_rp_and_flags(auth, rp_id)
    verify_signature(algorithm, public_key, signature, authenticator_data + hashlib.sha256(client_data_json).digest())
    new_count = int(auth["sign_count"])
    if (new_count or stored_sign_count) and new_count <= stored_sign_count:
        raise WebAuthnError("Signaturzaehler ist nicht gestiegen; der Passkey koennte kopiert worden sein")
    return new_count
