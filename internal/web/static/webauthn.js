// Security keys, browser side.
//
// The server can neither talk to a key nor read its answer: only the browser
// can, through navigator.credentials. This file is the go-between. It asks the
// server for a challenge, hands it to the key, and posts back what the key
// signed. Nothing here decides anything - every check happens on the server,
// because a check made here is a check an attacker can skip.
//
// Written as a separate file rather than inline, because the policy this server
// sends forbids inline scripts.

(function () {
  "use strict";

  // The WebAuthn API speaks in ArrayBuffers, the wire speaks base64url.

  function fromBase64(text) {
    var padded = text.replace(/-/g, "+").replace(/_/g, "/");
    var binary = window.atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function toBase64(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window
      .btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  function showError(message) {
    var box = document.querySelector("[data-webauthn-error]");
    if (!box) {
      window.alert(message);
      return;
    }
    box.textContent = message;
    box.hidden = false;
  }

  function clearError() {
    var box = document.querySelector("[data-webauthn-error]");
    if (box) {
      box.hidden = true;
    }
  }

  // supported reports whether a key can be used at all here. A page served
  // over plain HTTP, or reached by IP address, gets no API at all - so say so
  // rather than let a button do nothing.
  function supported() {
    return !!(window.PublicKeyCredential && window.isSecureContext);
  }

  function post(url, fields) {
    var body = new URLSearchParams();
    Object.keys(fields).forEach(function (name) {
      body.append(name, fields[name]);
    });

    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }).then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok) {
          throw new Error(data.message || "La demande a été refusée.");
        }
        return data;
      });
    });
  }

  // A key that is unplugged, not touched in time, or already enrolled reports
  // itself through an exception. The names are the useful part; the messages
  // browsers attach to them are not shown to anyone.
  function explain(error) {
    if (error.name === "NotAllowedError") {
      return "Aucune clé n'a répondu. Vérifie qu'elle est branchée, puis touche-la.";
    }
    if (error.name === "InvalidStateError") {
      return "Cette clé est déjà enregistrée sur ce compte.";
    }
    if (error.name === "SecurityError") {
      return "Le navigateur a refusé : la page doit être servie en HTTPS, sous un nom de machine et non une adresse IP.";
    }
    return error.message || "La clé n'a pas pu être utilisée.";
  }

  function registerKey(form) {
    var csrf = form.querySelector("[name=csrf]").value;
    var nameField = form.querySelector("[name=nom]");
    var name = nameField ? nameField.value : "";
    var button = form.querySelector("button[type=submit]");

    clearError();
    if (button) {
      button.disabled = true;
    }

    post("/parametres/cles/defi", { csrf: csrf })
      .then(function (options) {
        options.challenge = fromBase64(options.challenge);
        options.user.id = fromBase64(options.user.id);
        (options.excludeCredentials || []).forEach(function (credential) {
          credential.id = fromBase64(credential.id);
        });
        return navigator.credentials.create({ publicKey: options });
      })
      .then(function (credential) {
        return post("/parametres/cles", {
          csrf: csrf,
          nom: name,
          credential: JSON.stringify({
            id: toBase64(credential.rawId),
            clientDataJSON: toBase64(credential.response.clientDataJSON),
            attestationObject: toBase64(credential.response.attestationObject),
          }),
        });
      })
      .then(function (result) {
        window.location = result.redirect;
      })
      .catch(function (error) {
        showError(explain(error));
        if (button) {
          button.disabled = false;
        }
      });
  }

  function signInWithKey(form) {
    var csrf = form.querySelector("[name=login_csrf]").value;
    var button = form.querySelector("button[type=submit]");

    clearError();
    if (button) {
      button.disabled = true;
    }

    post("/login/cle/defi", { login_csrf: csrf })
      .then(function (options) {
        options.challenge = fromBase64(options.challenge);
        (options.allowCredentials || []).forEach(function (credential) {
          credential.id = fromBase64(credential.id);
        });
        return navigator.credentials.get({ publicKey: options });
      })
      .then(function (credential) {
        return post("/login/cle", {
          login_csrf: csrf,
          credential: JSON.stringify({
            id: toBase64(credential.rawId),
            clientDataJSON: toBase64(credential.response.clientDataJSON),
            authenticatorData: toBase64(credential.response.authenticatorData),
            signature: toBase64(credential.response.signature),
          }),
        });
      })
      .then(function (result) {
        window.location = result.redirect;
      })
      .catch(function (error) {
        showError(explain(error));
        if (button) {
          button.disabled = false;
        }
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var register = document.querySelector('[data-webauthn="register"]');
    var login = document.querySelector('[data-webauthn="login"]');
    if (!register && !login) {
      return;
    }

    if (!supported()) {
      var note = document.querySelector("[data-webauthn-unsupported]");
      if (note) {
        note.hidden = false;
      }
      [register, login].forEach(function (form) {
        if (!form) {
          return;
        }
        var button = form.querySelector("button[type=submit]");
        if (button) {
          button.disabled = true;
        }
      });
      return;
    }

    if (register) {
      register.addEventListener("submit", function (event) {
        event.preventDefault();
        registerKey(register);
      });
    }
    if (login) {
      login.addEventListener("submit", function (event) {
        event.preventDefault();
        signInWithKey(login);
      });
    }
  });
})();
