(function () {
    'use strict';

    const cfg = window.jwtAuth;
    if (!cfg?.loginUrl) return;

    function inject(form) {
        if (form.dataset.jwtAuthDone) return;
        form.dataset.jwtAuthDone = '1';

        const wrap = document.createElement('div');
        wrap.className = 'jwt-auth-sso';
        wrap.innerHTML = `<a href="${cfg.loginUrl}" class="woocommerce-button button">${cfg.buttonLabel}</a>`;
        form.prepend(wrap);
    }

    function scan() {
        document.querySelectorAll(
            '.woocommerce-form-login, .wc-block-components-form, .wp-block-woocommerce-customer-account form'
        ).forEach(inject);
    }

    scan();

    const observer = new MutationObserver(scan);
    observer.observe(document.body, { childList: true, subtree: true });

    // Disconnect after 8 s — block forms are typically rendered well within this window.
    setTimeout(() => observer.disconnect(), 8000);
})();
