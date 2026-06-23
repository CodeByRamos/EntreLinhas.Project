// Script para melhorar a experiência de postagem
document.addEventListener('DOMContentLoaded', function() {
    // Elementos do formulário
    const postForm = document.getElementById('post-form');
    const conteudoTextarea = document.getElementById('conteudo');
    const categoriaSelect = document.getElementById('categoria');
    const charCount = document.getElementById('char-count');
    const maxLength = 2000; // Limite maximo de caracteres
    const minLength = 3;  // Limite minimo de caracteres
    const submitButton = document.getElementById('submit-button');
    const remainingChars = document.getElementById('remaining-chars');
    const sensitiveAck = document.getElementById('sensitive_ack');
    const sensitiveRisk = document.getElementById('sensitive_risk');
    const sensitiveModal = document.getElementById('sensitive-modal');
    const sensitiveModalTitle = document.getElementById('sensitive-modal-title');
    const sensitiveModalMessage = document.getElementById('sensitive-modal-message');
    const sensitiveModalSupport = document.getElementById('sensitive-modal-support');
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
        
        // Cores do contador no tema v2 (tokens), e estado do botão de envio.
        const setCounterColor = (color, bold) => {
            charCount.style.color = color;
            remainingChars.style.color = color;
            charCount.style.fontWeight = bold ? '700' : '';
            remainingChars.style.fontWeight = bold ? '700' : '';
        };
        const setSubmitEnabled = (enabled) => {
            if (!submitButton) return;
            submitButton.disabled = !enabled;
            submitButton.classList.toggle('opacity-50', !enabled);
            submitButton.classList.toggle('cursor-not-allowed', !enabled);
        };

        if (count > maxLength) {
            setCounterColor('var(--danger)', true);
            setSubmitEnabled(false);
        } else if (count > maxLength * 0.8) {
            setCounterColor('#e2b76e', false);   // âmbar suave (atenção)
            setSubmitEnabled(true);
        } else if (count < minLength) {
            setCounterColor('#e2b76e', false);
            setSubmitEnabled(false);
        } else {
            setCounterColor('var(--text-muted)', false);
            setSubmitEnabled(true);
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
            
            // Destacar campos com erro (classe v2 que o .input-modern reconhece)
            if (conteudo.length < minLength || conteudo.length > maxLength) {
                conteudoTextarea.classList.add('input-error');
            }
            if (!categoria) {
                categoriaSelect.classList.add('input-error');
            }
        }
        
        return isValid;
    }
    
     function openSensitiveModal(responseData) {
        if (!sensitiveModal || !responseData) return;
        sensitiveModalTitle.textContent = responseData.title || 'Um cuidado para você';
        sensitiveModalMessage.textContent = responseData.message || '';
        if (sensitiveModalSupport) {
            sensitiveModalSupport.textContent = responseData.support_message || '';
            sensitiveModalSupport.classList.toggle('hidden', !responseData.support_message);
        }
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
    
    // Remover destaque de erro ao interagir com os campos
    if (conteudoTextarea) {
        conteudoTextarea.addEventListener('focus', function() {
            this.classList.remove('input-error');
        });
    }

    if (categoriaSelect) {
        categoriaSelect.addEventListener('focus', function() {
            this.classList.remove('input-error');
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
                const gate = data && data.gate ? data.gate : (data && data.risk_level !== 'LOW' ? 'ack' : 'none');
                if (!data || gate === 'none') {
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
