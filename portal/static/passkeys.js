// Passkey login and registration. The portal's CSP allows only same-origin
// scripts, so the ceremonies live here instead of inline handlers.
(function () {
  "use strict";

  function toBytes(value) {
    var base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) base64 += "=";
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function toText(buffer) {
    if (!buffer) return "";
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
  }

  async function postJson(url, body, csrf) {
    var headers = { "Content-Type": "application/json" };
    if (csrf) headers["X-CSRF-Token"] = csrf;
    var response = await fetch(url, {
      method: "POST", headers: headers, credentials: "same-origin", body: JSON.stringify(body || {}),
    });
    var data = {};
    try { data = await response.json(); } catch (error) { data = {}; }
    if (!response.ok) throw new Error(data.error || data.detail || ("HTTP " + response.status));
    return data;
  }

  function showError(target, error) {
    if (!target) return;
    var message = error && error.name === "NotAllowedError"
      ? "Vorgang abgebrochen oder Zeit abgelaufen."
      : (error && error.message) || String(error);
    target.textContent = message;
    target.hidden = false;
  }

  async function login(button) {
    var errorBox = document.getElementById("passkey-error");
    if (errorBox) errorBox.hidden = true;
    button.disabled = true;
    try {
      var options = await postJson("/login/passkey/options");
      var publicKey = options.publicKey;
      publicKey.challenge = toBytes(publicKey.challenge);
      var credential = await navigator.credentials.get({ publicKey: publicKey });
      var result = await postJson("/login/passkey", {
        flow: options.flow,
        id: credential.id,
        clientDataJSON: toText(credential.response.clientDataJSON),
        authenticatorData: toText(credential.response.authenticatorData),
        signature: toText(credential.response.signature),
        userHandle: toText(credential.response.userHandle),
      });
      window.location.assign(result.redirect || "/");
    } catch (error) {
      showError(errorBox, error);
      button.disabled = false;
    }
  }

  async function register(button) {
    var errorBox = document.getElementById("passkey-error");
    var nameField = document.getElementById("passkey-name");
    var csrf = button.getAttribute("data-csrf");
    if (errorBox) errorBox.hidden = true;
    button.disabled = true;
    try {
      var options = await postJson("/account/passkeys/options", {}, csrf);
      var publicKey = options.publicKey;
      publicKey.challenge = toBytes(publicKey.challenge);
      publicKey.user.id = toBytes(publicKey.user.id);
      publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map(function (item) {
        return { type: item.type, id: toBytes(item.id) };
      });
      var credential = await navigator.credentials.create({ publicKey: publicKey });
      var transports = typeof credential.response.getTransports === "function"
        ? credential.response.getTransports() : [];
      var result = await postJson("/account/passkeys", {
        flow: options.flow,
        id: credential.id,
        name: nameField ? nameField.value : "",
        clientDataJSON: toText(credential.response.clientDataJSON),
        attestationObject: toText(credential.response.attestationObject),
        transports: transports,
      }, csrf);
      window.location.assign(result.redirect || "/account");
    } catch (error) {
      showError(errorBox, error);
      button.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var loginButton = document.getElementById("passkey-login");
    var registerButton = document.getElementById("passkey-register");
    var unsupported = document.getElementById("passkey-unsupported");
    if (!supported()) {
      if (loginButton) loginButton.hidden = true;
      if (registerButton) registerButton.disabled = true;
      if (unsupported) unsupported.hidden = false;
      return;
    }
    if (loginButton) {
      loginButton.hidden = false;
      loginButton.addEventListener("click", function () { login(loginButton); });
    }
    if (registerButton) registerButton.addEventListener("click", function () { register(registerButton); });
  });
})();
