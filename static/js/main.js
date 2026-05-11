// Funcionalidades gerais do EntreLinhas

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
