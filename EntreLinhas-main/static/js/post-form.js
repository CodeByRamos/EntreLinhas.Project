// Script para melhorar a experiência de postagem
document.addEventListener('DOMContentLoaded', function() {
    // Elementos do formulário
    const postForm = document.getElementById('post-form');
    const conteudoTextarea = document.getElementById('conteudo');
    const categoriaSelect = document.getElementById('categoria');
    const charCount = document.getElementById('char-count');
    const maxLength = 500; // Limite máximo de caracteres
    const minLength = 10;  // Limite mínimo de caracteres
    const submitButton = document.getElementById('submit-button');
    const remainingChars = document.getElementById('remaining-chars');
    
    // Função para atualizar o contador de caracteres
    function updateCharCount() {
        if (!conteudoTextarea || !charCount || !remainingChars) return;
        
        const count = conteudoTextarea.value.length;
        charCount.textContent = count;
        
        // Calcular caracteres restantes
        const remaining = maxLength - count;
        remainingChars.textContent = remaining;
        
        // Atualizar classes de estilo com base na contagem
        if (count > maxLength) {
            charCount.classList.add('text-red-500', 'font-bold');
            charCount.classList.remove('text-gray-500', 'text-yellow-500');
            remainingChars.classList.add('text-red-500', 'font-bold');
            remainingChars.classList.remove('text-gray-500', 'text-yellow-500');
            
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.classList.add('opacity-50', 'cursor-not-allowed');
                submitButton.classList.remove('hover:bg-primary-700');
            }
        } else if (count > maxLength * 0.8) {
            // Acima de 80% do limite
            charCount.classList.add('text-yellow-500');
            charCount.classList.remove('text-red-500', 'text-gray-500', 'font-bold');
            remainingChars.classList.add('text-yellow-500');
            remainingChars.classList.remove('text-red-500', 'text-gray-500', 'font-bold');
            
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.classList.remove('opacity-50', 'cursor-not-allowed');
                submitButton.classList.add('hover:bg-primary-700');
            }
        } else if (count < minLength) {
            // Abaixo do mínimo
            charCount.classList.add('text-yellow-500');
            charCount.classList.remove('text-red-500', 'text-gray-500', 'font-bold');
            remainingChars.classList.add('text-yellow-500');
            remainingChars.classList.remove('text-red-500', 'text-gray-500', 'font-bold');
            
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.classList.add('opacity-50', 'cursor-not-allowed');
                submitButton.classList.remove('hover:bg-primary-700');
            }
        } else {
            // Normal
            charCount.classList.add('text-gray-500');
            charCount.classList.remove('text-red-500', 'text-yellow-500', 'font-bold');
            remainingChars.classList.add('text-gray-500');
            remainingChars.classList.remove('text-red-500', 'text-yellow-500', 'font-bold');
            
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.classList.remove('opacity-50', 'cursor-not-allowed');
                submitButton.classList.add('hover:bg-primary-700');
            }
        }
    }
    
    // Função para validar o formulário antes do envio
    function validateForm(e) {
        if (!conteudoTextarea || !categoriaSelect) return true;
        
        let isValid = true;
        let errorMessage = '';
        
        // Validar conteúdo
        const conteudo = conteudoTextarea.value.trim();
        if (conteudo.length < minLength) {
            errorMessage = `O desabafo deve ter pelo menos ${minLength} caracteres.`;
            isValid = false;
        } else if (conteudo.length > maxLength) {
            errorMessage = `O desabafo não pode ter mais de ${maxLength} caracteres.`;
            isValid = false;
        }
        
        // Validar categoria
        const categoria = categoriaSelect.value;
        if (!categoria) {
            errorMessage += ' Por favor, selecione uma categoria.';
            isValid = false;
        }
        
        // Se houver erros, impedir o envio e mostrar mensagem
        if (!isValid) {
            e.preventDefault();
            
            // Mostrar mensagem de erro
            const errorElement = document.getElementById('form-error');
            if (errorElement) {
                errorElement.textContent = errorMessage;
                errorElement.classList.remove('hidden');
                
                // Esconder a mensagem após 5 segundos
                setTimeout(() => {
                    errorElement.classList.add('hidden');
                }, 5000);
            }
            
            // Destacar campos com erro
            if (conteudo.length < minLength || conteudo.length > maxLength) {
                conteudoTextarea.classList.add('border-red-500', 'focus:ring-red-500');
                conteudoTextarea.classList.remove('border-gray-300', 'focus:ring-primary-500');
            }
            
            if (!categoria) {
                categoriaSelect.classList.add('border-red-500', 'focus:ring-red-500');
                categoriaSelect.classList.remove('border-gray-300', 'focus:ring-primary-500');
            }
        }
        
        return isValid;
    }
    
    // Adicionar evento de input para o textarea
    if (conteudoTextarea) {
        conteudoTextarea.addEventListener('input', updateCharCount);
        
        // Auto-resize do textarea
        conteudoTextarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
        
        // Inicializar contador
        updateCharCount();
    }
    
    // Remover classes de erro ao interagir com os campos
    if (conteudoTextarea) {
        conteudoTextarea.addEventListener('focus', function() {
            this.classList.remove('border-red-500', 'focus:ring-red-500');
            this.classList.add('border-gray-300', 'focus:ring-primary-500');
        });
    }
    
    if (categoriaSelect) {
        categoriaSelect.addEventListener('focus', function() {
            this.classList.remove('border-red-500', 'focus:ring-red-500');
            this.classList.add('border-gray-300', 'focus:ring-primary-500');
        });
    }
    
    // Adicionar validação ao envio do formulário
    if (postForm) {
        postForm.addEventListener('submit', validateForm);
    }
    
    // Adicionar animação de digitação
    if (conteudoTextarea) {
        conteudoTextarea.addEventListener('focus', function() {
            this.classList.add('animate-pulse-light');
        });
        
        conteudoTextarea.addEventListener('blur', function() {
            this.classList.remove('animate-pulse-light');
        });
    }
});

