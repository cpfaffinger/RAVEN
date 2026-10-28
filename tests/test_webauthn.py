import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))

import webauthn  # noqa: E402


RP_ID = "backup.example.com"
ORIGIN = "https://backup.example.com:49180"
CHALLENGE = b"c" * 32
CREDENTIAL_ID = b"credential-0001"


def cbor(value):
    """Encode the CBOR subset the tests need."""
    def head(major, length):
        if length < 24:
            return bytes([major << 5 | length])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if length < 1 << (8 * size):
                return bytes([major << 5 | info]) + length.to_bytes(size, "big")
        raise ValueError(length)

    if value is None:
        return bytes([0xF6])
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(value)


def client_data(ceremony, *, challenge=CHALLENGE, origin=ORIGIN):
    return json.dumps({
        "type": ceremony, "challenge": webauthn.b64url_encode(challenge), "origin": origin, "crossOrigin": False,
    }).encode()


def auth_data(*, flags=0x05, count=0, rp_id=RP_ID, cose=None):
    data = hashlib.sha256(rp_id.encode()).digest()
    if cose is not None:
        flags |= 0x40
    data += bytes([flags]) + struct.pack(">I", count)
    if cose is not None:
        data += b"\x00" * 16 + struct.pack(">H", len(CREDENTIAL_ID)) + CREDENTIAL_ID + cbor(cose)
    return data


def ec_cose(private_key):
    numbers = private_key.public_key().public_numbers()
    return {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())

    def register(self, **overrides):
        arguments = {
            "client_data_json": client_data("webauthn.create"),
            "attestation_object": cbor({"fmt": "none", "attStmt": {}, "authData": auth_data(cose=ec_cose(self.key))}),
            "challenge": CHALLENGE, "origin": ORIGIN, "rp_id": RP_ID,
        }
        arguments.update(overrides)
        return webauthn.verify_registration(**arguments)

    def test_accepts_a_none_attestation(self):
        credential = self.register()
        self.assertEqual(credential["credential_id"], webauthn.b64url_encode(CREDENTIAL_ID))
        self.assertEqual(credential["algorithm"], webauthn.ALG_ES256)
        self.assertEqual(credential["public_key"], webauthn.public_key_der(self.key.public_key()))

    def test_rejects_foreign_origin_challenge_and_ceremony(self):
        for overrides in (
            {"client_data_json": client_data("webauthn.create", origin="https://evil.example")},
            {"client_data_json": client_data("webauthn.create", challenge=b"x" * 32)},
            {"client_data_json": client_data("webauthn.get")},
        ):
            with self.assertRaises(webauthn.WebAuthnError):
                self.register(**overrides)

    def test_rejects_another_relying_party_and_missing_verification(self):
        for data in (
            auth_data(rp_id="evil.example", cose=ec_cose(self.key)),
            auth_data(flags=0x01, cose=ec_cose(self.key)),
        ):
            with self.assertRaises(webauthn.WebAuthnError):
                self.register(attestation_object=cbor({"fmt": "none", "attStmt": {}, "authData": data}))

    def test_rejects_truncated_data(self):
        with self.assertRaises(webauthn.WebAuthnError):
            self.register(attestation_object=cbor({"fmt": "none", "attStmt": {}, "authData": b"\x00" * 20}))


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public = webauthn.public_key_der(self.key.public_key())

    def login(self, *, count=1, stored=0, key=None, data=None, client=None, algorithm=webauthn.ALG_ES256):
        authenticator = data if data is not None else auth_data(count=count)
        client_json = client or client_data("webauthn.get")
        signer = key or self.key
        signed = authenticator + hashlib.sha256(client_json).digest()
        signature = signer.sign(signed, ec.ECDSA(hashes.SHA256()))
        return webauthn.verify_authentication(
            client_data_json=client_json, authenticator_data=authenticator, signature=signature,
            challenge=CHALLENGE, origin=ORIGIN, rp_id=RP_ID, public_key=self.public,
            algorithm=algorithm, stored_sign_count=stored,
        )

    def test_valid_assertion_returns_the_new_counter(self):
        self.assertEqual(self.login(count=7, stored=6), 7)

    def test_synced_passkeys_without_counter_are_accepted(self):
        self.assertEqual(self.login(count=0, stored=0), 0)

    def test_counter_regression_is_refused(self):
        with self.assertRaises(webauthn.WebAuthnError):
            self.login(count=5, stored=5)

    def test_signature_of_another_key_is_refused(self):
        with self.assertRaises(webauthn.WebAuthnError):
            self.login(key=ec.generate_private_key(ec.SECP256R1()))

    def test_replayed_registration_data_cannot_log_in(self):
        with self.assertRaises(webauthn.WebAuthnError):
            self.login(client=client_data("webauthn.create"))

    def test_ed25519_passkeys(self):
        key = ed25519.Ed25519PrivateKey.generate()
        cose = {1: 1, 3: -8, -1: 6, -2: key.public_key().public_bytes_raw()}
        algorithm, public = webauthn.cose_public_key(cose)
        authenticator = auth_data(count=0)
        client_json = client_data("webauthn.get")
        signature = key.sign(authenticator + hashlib.sha256(client_json).digest())
        self.assertEqual(
            webauthn.verify_authentication(
                client_data_json=client_json, authenticator_data=authenticator, signature=signature,
                challenge=CHALLENGE, origin=ORIGIN, rp_id=RP_ID, public_key=webauthn.public_key_der(public),
                algorithm=algorithm, stored_sign_count=0,
            ),
            0,
        )


class CborTests(unittest.TestCase):
    def test_round_trip_of_nested_values(self):
        value = {"a": [1, -2, b"\x00", "ü", True, None], 3: {-1: 2**40}}
        self.assertEqual(webauthn.cbor_decode(cbor(value))[0], value)

    def test_trailing_bytes_are_refused(self):
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.cbor_decode(cbor(1) + b"\x00")

    def test_deep_nesting_is_refused(self):
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.cbor_decode(b"\x81" * 40 + b"\x00")


if __name__ == "__main__":
    unittest.main()
