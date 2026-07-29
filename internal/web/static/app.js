// Confirmation before a destructive action.
//
// The handler is attached here rather than written as an onsubmit attribute in
// the markup, because SYNSEC's content security policy forbids inline scripts.
// An inline handler would be silently dropped by the browser - and a delete
// button that never asks is worse than one that asks awkwardly.
// Suggest an identifier while the label is being typed.
//
// Only a suggestion: the field stays editable, and once someone has typed in
// it the suggestion stops overwriting what they wrote. The server derives the
// same slug when the field is left empty, so this is a convenience and never
// the thing the identifier depends on.
document.addEventListener("DOMContentLoaded", function () {
  var source = document.querySelector("[data-slug-source]");
  var target = document.querySelector("[data-slug-target]");
  if (!source || !target) {
    return;
  }

  var touched = false;
  target.addEventListener("input", function () {
    touched = true;
  });

  source.addEventListener("input", function () {
    if (touched) {
      return;
    }
    target.value = source.value
      .normalize("NFD")
      .replace(/[̀-ͯ]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "");
  });
});

document.addEventListener("submit", function (event) {
  var form = event.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  var message = form.dataset.confirm;
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});

// Copy to the clipboard.
//
// The most frequent thing anyone does with a secrets manager is copy a value,
// and until now that meant selecting the text by hand. A button marked with
// data-copy points at the element holding the value; the label confirms what
// happened and goes back to normal on its own.
//
// Copying works whether or not the value is on screen, which is the point: the
// safest way to move a password is one that never displays it.
document.addEventListener("click", function (event) {
  if (!(event.target instanceof Element)) {
    return;
  }
  var button = event.target.closest("[data-copy]");
  if (!button) {
    return;
  }
  event.preventDefault();

  var source = document.querySelector(button.dataset.copy);
  if (!source) {
    return;
  }
  var text = "value" in source ? source.value : source.textContent;

  say(button, function () {
    return navigator.clipboard.writeText(text);
  });
});

// say swaps a button's label while an action reports back, then restores it.
function say(button, run) {
  var original = button.textContent;
  var restore = function (message) {
    button.textContent = message;
    window.setTimeout(function () {
      button.textContent = original;
    }, 1600);
  };

  try {
    run().then(
      function () {
        restore("Copié");
      },
      function () {
        restore("Échec");
      }
    );
  } catch (error) {
    restore("Échec");
  }
}

// Controls that do nothing without scripting stay hidden until it runs, so a
// page never offers a button that cannot work.
document.addEventListener("DOMContentLoaded", function () {
  var scripted = document.querySelectorAll("[data-needs-js]");
  Array.prototype.forEach.call(scripted, function (element) {
    element.hidden = false;
  });

  // Drawing a value needs a secure context. SYNSEC has no plain-HTTP mode, so
  // this only ever bites in an odd setup - and there the button is removed
  // rather than left to fail silently.
  if (!(window.crypto && window.crypto.getRandomValues)) {
    var generators = document.querySelectorAll("[data-generate]");
    Array.prototype.forEach.call(generators, function (button) {
      button.remove();
    });
  }
});

// Show a secret without putting the cursor in it.
//
// The value used to uncover itself when the field took focus, which made
// reading and editing the same gesture: one stray keystroke away from a new
// version nobody meant to save. Showing is now a deliberate press, and the
// field stays read-only until it happens.
//
// Without scripting the page keeps its old behaviour - focus uncovers - so
// nothing here is required to read a secret, only to read one safely.
document.addEventListener("DOMContentLoaded", function () {
  var fields = document.querySelectorAll("[data-secret-field]");

  Array.prototype.forEach.call(fields, function (field) {
    var value = field.querySelector("textarea, input");
    var actions = field.querySelector("[data-secret-actions]");
    var toggle = field.querySelector("[data-reveal]");
    if (!value || !actions) {
      return;
    }

    // A field the server marked read-only belongs to someone who was given
    // this secret to read, not to change. Showing it must not hand them a
    // field they can type in.
    var readOnlyAlways = value.hasAttribute("readonly");

    // Marks the field as script-driven: the stylesheet stops uncovering on
    // focus, and the buttons appear.
    field.classList.add("has-actions");
    actions.hidden = false;
    value.readOnly = true;

    if (!toggle) {
      return;
    }
    toggle.addEventListener("click", function () {
      var covered = value.classList.toggle("masked");
      value.readOnly = covered || readOnlyAlways;
      toggle.textContent = covered ? "Afficher" : "Masquer";
      if (!covered) {
        value.focus();
      }
    });
  });
});

// Narrow a list that is already on screen.
//
// A round trip to filter rows the browser is holding would be slower and would
// cost a page render for every keystroke. This only ever hides rows the server
// already decided this account may see.
document.addEventListener("DOMContentLoaded", function () {
  var boxes = document.querySelectorAll("[data-filter]");

  Array.prototype.forEach.call(boxes, function (box) {
    var table = document.querySelector(box.dataset.filter);
    if (!table) {
      return;
    }
    var rows = table.querySelectorAll("tbody tr");
    var count = document.querySelector("[data-filter-count]");

    box.addEventListener("input", function () {
      var needle = fold(box.value);
      var shown = 0;

      Array.prototype.forEach.call(rows, function (row) {
        var hit = needle === "" || fold(row.textContent).indexOf(needle) !== -1;
        row.hidden = !hit;
        if (hit) {
          shown++;
        }
      });

      if (count) {
        count.textContent = needle === "" ? "" : shown + " sur " + rows.length;
      }
    });
  });
});

// fold matches the server's own comparison: lower case, accents removed, so
// "sauvegarde" finds "Sauvegardé" and the filter agrees with the search page.
function fold(text) {
  return text
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}

// Try an appearance before keeping it.
//
// The size and the palette both ride on one class on the root element, and
// that class is written by the server on every page. So a preview is nothing
// more than editing it here: navigate away without saving and the next page
// arrives with the stored choice, unchanged. Nothing is written anywhere until
// the form is submitted.
document.addEventListener("DOMContentLoaded", function () {
  var form = document.querySelector("[data-appearance]");
  if (!form) {
    return;
  }

  var root = document.documentElement;
  var scale = form.querySelector("[name=scale]");
  var theme = form.querySelector("[name=theme]");
  var saved = root.className;

  function preview() {
    // Only the two families this form owns are touched, so a class put there
    // by anything else survives.
    Array.prototype.slice.call(root.classList).forEach(function (name) {
      if (/^(scale|theme)-/.test(name)) {
        root.classList.remove(name);
      }
    });

    // A value equal to the default is absent from the page rather than written
    // out, which is what the server does too.
    if (scale && scale.value !== form.dataset.defaultScale) {
      root.classList.add("scale-" + scale.value);
    }
    if (theme && theme.value !== form.dataset.defaultTheme) {
      root.classList.add("theme-" + theme.value);
    }
  }

  [scale, theme].forEach(function (field) {
    if (field) {
      field.addEventListener("change", preview);
    }
  });

  // Put the saved appearance back before the page is stored for the back
  // button, so returning to it does not restore a preview nobody kept.
  window.addEventListener("pagehide", function () {
    root.className = saved;
  });
});

// Generate a value rather than invent one.
//
// Drawn here rather than on the server: the value then crosses the network
// exactly once, when the form is submitted, instead of once on the way out and
// once on the way back. The browser's generator is the same primitive a
// security key uses to sign, so nothing is lost by asking it.
//
// Letters and digits only, deliberately. These values end up in a secrets.yaml
// and in environment variables, where a quote, a backslash or a dollar sign
// changes meaning and the failure shows up days later in a device that will
// not start. The length makes up for the smaller alphabet several times over:
// thirty-two characters out of sixty-two is a hundred and ninety bits.
var secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
var secretLength = 32;

function newSecret(length) {
  // Bytes at or above this would fold unevenly onto the alphabet and make some
  // characters likelier than others. Drawing again costs nothing and is the
  // difference between random and nearly random.
  var limit = 256 - (256 % secretAlphabet.length);
  var buffer = new Uint8Array(length * 2);
  var out = "";

  while (out.length < length) {
    window.crypto.getRandomValues(buffer);
    for (var i = 0; i < buffer.length && out.length < length; i++) {
      if (buffer[i] < limit) {
        out += secretAlphabet.charAt(buffer[i] % secretAlphabet.length);
      }
    }
  }
  return out;
}

document.addEventListener("click", function (event) {
  if (!(event.target instanceof Element)) {
    return;
  }
  var button = event.target.closest("[data-generate]");
  if (!button) {
    return;
  }
  event.preventDefault();

  var target = document.querySelector(button.dataset.generate);
  if (!target) {
    return;
  }
  target.value = newSecret(secretLength);

  // A value that arrives covered would be a value nobody asked to hide. The
  // existing control is used rather than a second path to the same state, so
  // a field the server made read-only stays read-only.
  var field = button.closest("[data-secret-field]");
  if (field) {
    var toggle = field.querySelector("[data-reveal]");
    if (toggle && target.classList.contains("masked")) {
      toggle.click();
    }
  }
  target.focus();
});
