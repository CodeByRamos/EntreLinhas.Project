// Arquivo JavaScript principal para funcionalidades gerais do site

document.addEventListener('DOMContentLoaded', function() {
    // Animações de entrada para elementos da página
    const animateElements = document.querySelectorAll('.animate-fade-in-down, .animate-fade-slide-up, .animate-scale-up');
    
    if (animateElements.length > 0) {
        // Adiciona classes de animação com atraso para criar efeito cascata
        animateElements.forEach((element, index) => {
            setTimeout(() => {
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
            }, 100 * index);
        });
    }
    
    // Detecta preferência de tema escuro/claro do sistema
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }
    
    // Adiciona listener para mudanças na preferência de tema
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', event => {
        if (event.matches) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    });
    
    // Fecha mensagens flash após alguns segundos
    const flashMessages = document.querySelectorAll('[role="alert"]');
    if (flashMessages.length > 0) {
        setTimeout(() => {
            flashMessages.forEach(message => {
                message.style.opacity = '0';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 500);
            });
        }, 5000);
    }
});

