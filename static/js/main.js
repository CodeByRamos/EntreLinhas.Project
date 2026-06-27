// Funcionalidades gerais do EntreLinhas

// --- CSRF: injeta o token em toda requisição fetch same-origin que altera estado ---
// Assim, todos os endpoints JSON (comentar, reagir, ecoar, denunciar) ficam
// protegidos sem precisar editar cada chamada individualmente.
(function () {
    var meta = document.querySelector('meta[name="csrf-token"]');
    var token = meta ? meta.getAttribute('content') : '';
    if (!token || !window.fetch) return;
    var SAFE = { GET: 1, HEAD: 1, OPTIONS: 1, TRACE: 1 };
    var nativeFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
        init = init || {};
        var method = (init.method || (typeof input !== 'string' && input && input.method) || 'GET').toUpperCase();
        // Só mexe em requisições same-origin que mudam estado.
        var url = typeof input === 'string' ? input : (input && input.url) || '';
        var sameOrigin = !/^https?:\/\//i.test(url) || url.indexOf(window.location.origin) === 0;
        if (!SAFE[method] && sameOrigin) {
            var headers = new Headers(init.headers || (typeof input !== 'string' && input && input.headers) || {});
            if (!headers.has('X-CSRFToken')) headers.set('X-CSRFToken', token);
            init.headers = headers;
        }
        return nativeFetch(input, init);
    };
})();

document.addEventListener('DOMContentLoaded', function() {
    document.documentElement.classList.add('dark');

    const animateElements = document.querySelectorAll('.animate-fade-in-down, .animate-fade-slide-up, .animate-scale-up');
    if (animateElements.length > 0) {
        animateElements.forEach((element, index) => {
            setTimeout(() => {
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
            }, 100 * index);
        });
    }

    // Auto-dismiss apenas dos avisos transitórios (sucesso/info = role="status").
    // Erros (role="alert") permanecem até a pessoa navegar, para não sumirem cedo demais.
    const transientMessages = document.querySelectorAll('.flash-message[role="status"]');
    if (transientMessages.length > 0) {
        setTimeout(() => {
            transientMessages.forEach(message => {
                message.style.opacity = '0';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 500);
            });
        }, 6000);
    }
});

// PWA: registra o service worker (habilita instalar na tela inicial). É
// pass-through, sem cache — então nunca serve conteúdo obsoleto.
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
        navigator.serviceWorker.register('/sw.js').catch(function () {});
    });
}
