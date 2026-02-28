(function () {
  'use strict';

  document.addEventListener('click', function (e) {
    var el = e.target.closest('[data-confirm]');
    if (el && !confirm(el.dataset.confirm)) {
      e.preventDefault();
    }
  });

  document.addEventListener('submit', function (e) {
    var form = e.target.closest('[data-confirm-submit]');
    if (form && !confirm(form.dataset.confirmSubmit)) {
      e.preventDefault();
    }
  });
})();
