// Script para melhorar a experiência de postagem
document.addEventListener('DOMContentLoaded', function() {
    // Elementos do formulário
    const postForm = document.getElementById('post-form');
    const conteudoTextarea = document.getElementById('conteudo');
    const categoriaSelect = document.getElementById('categoria');
    const charCount = document.getElementById('char-count');
    const maxLength = 1000; // Limite máximo de caracteres
    const minLength = 10;  // Limite mínimo de caracteres
    const submitButton = document.getElementById('submit-button');
    const remainingChars = document.getElementById('remaining-chars');
    const sensitiveAck = document.getElementById('sensitive_ack');
    const sensitiveRisk = document.getElementById('sensitive_risk');
    const sensitiveModal = document.getElementById('sensitive-modal');
    const sensitiveModalTitle = document.getElementById('sensitive-modal-title');
    const sensitiveModalMessage = document.getElementById('sensitive-modal-message');
    const sensitiveHelp = document.getElementById('sensitive-help');
    const sensitiveBlockReason = document.getElementById('sensitive-block-reason');
    const sensitiveContinue = document.getElementById('sensitive-continue');
    const sensitiveEdit = document.getElementById('sensitive-edit');
    let allowSubmitOnce = false;
    let pendingSubmitter = null;
    
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
    
     function openSensitiveModal(responseData) {
        if (!sensitiveModal || !responseData) return;
        sensitiveModalTitle.textContent = responseData.title || 'Um cuidado para você';
        sensitiveModalMessage.textContent = responseData.message || '';
        sensitiveHelp.classList.toggle('hidden', !responseData.show_help_contacts);

        const isBlocked = !responseData.allow_continue;
        sensitiveContinue.classList.toggle('hidden', isBlocked);
        sensitiveBlockReason.classList.toggle('hidden', !isBlocked);
        sensitiveBlockReason.textContent = isBlocked ? (responseData.block_reason || '') : '';

        sensitiveModal.classList.remove('hidden');
        sensitiveModal.classList.add('flex');
    }

    function closeSensitiveModal() {
        if (!sensitiveModal) return;
        sensitiveModal.classList.add('hidden');
        sensitiveModal.classList.remove('flex');
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
        postForm.addEventListener('submit', async function(e) {
            if (!validateForm(e)) return;
            if (allowSubmitOnce) {
                allowSubmitOnce = false;
                return;
            }

            const action = (e.submitter && e.submitter.value) || 'publish';
            if (action !== 'publish') {
                return;
            }

            e.preventDefault();
            pendingSubmitter = e.submitter || submitButton;

            if (sensitiveAck) sensitiveAck.value = '0';
            if (sensitiveRisk) sensitiveRisk.value = '';

            try {
                const analysisResponse = await fetch('/analyze-content', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        text: conteudoTextarea ? conteudoTextarea.value : ''
                    })
                });

                if (!analysisResponse.ok) {
                    allowSubmitOnce = true;
                    postForm.requestSubmit(pendingSubmitter);
                    return;
                }

                const data = await analysisResponse.json();
                if (!data || data.risk_level === 'LOW') {
                    allowSubmitOnce = true;
                    postForm.requestSubmit(pendingSubmitter);
                    return;
                }

                if (sensitiveRisk) sensitiveRisk.value = data.risk_level;
                openSensitiveModal(data.response);
            } catch (_) {
                allowSubmitOnce = true;
                postForm.requestSubmit(pendingSubmitter);
            }
        });
    }

    if (sensitiveContinue) {
        sensitiveContinue.addEventListener('click', function() {
            if (sensitiveAck) sensitiveAck.value = '1';
            closeSensitiveModal();
            allowSubmitOnce = true;
            postForm.requestSubmit(pendingSubmitter || submitButton);
        });
    }

    if (sensitiveEdit) {
        sensitiveEdit.addEventListener('click', function() {
            if (sensitiveAck) sensitiveAck.value = '0';
            closeSensitiveModal();
            if (conteudoTextarea) conteudoTextarea.focus();
        });
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