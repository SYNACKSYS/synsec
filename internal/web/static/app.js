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
