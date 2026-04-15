// Gerenciamento de tema (claro/escuro) com persistência via localStorage
document.addEventListener('DOMContentLoaded', function() {
    // Elementos do DOM
    const themeToggleBtn = document.getElementById('theme-toggle');
    const themeToggleIcon = document.getElementById('theme-toggle-icon');
    const htmlElement = document.documentElement;
    
    // Verifica se há uma preferência salva no localStorage
    const savedTheme = localStorage.getItem('theme');
    
    // Função para atualizar a aparência do botão de alternância
    function updateToggleAppearance(isDark) {
        if (isDark) {
            // Modo escuro ativo
            themeToggleIcon.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd" />
                </svg>
            `;
            themeToggleBtn.setAttribute('title', 'Mudar para modo claro');
        } else {
            // Modo claro ativo
            themeToggleIcon.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
                </svg>
            `;
            themeToggleBtn.setAttribute('title', 'Mudar para modo escuro');
        }
    }
    
    // Função para aplicar o tema
    function applyTheme(theme) {
        if (theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            htmlElement.classList.add('dark');
            updateToggleAppearance(true);
        } else {
            htmlElement.classList.remove('dark');
            updateToggleAppearance(false);
        }
    }
    
    // Aplicar tema inicial
    if (savedTheme) {
        applyTheme(savedTheme);
    } else {
        // Se não houver preferência salva, usar preferência do sistema
        const systemPreference = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        applyTheme(systemPreference);
        localStorage.setItem('theme', systemPreference);
    }
    
    // Adicionar evento de clique ao botão de alternância
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', function() {
            const isDark = htmlElement.classList.contains('dark');
            const newTheme = isDark ? 'light' : 'dark';
            
            // Aplicar novo tema
            applyTheme(newTheme);
            
            // Salvar preferência
            localStorage.setItem('theme', newTheme);
        });
    }
    
    // Observar mudanças na preferência do sistema
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', event => {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'system') {
            applyTheme('system');
        }
    });
});

