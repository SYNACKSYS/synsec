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
