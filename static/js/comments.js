// Arquivo JavaScript para gerenciar comentários

document.addEventListener('DOMContentLoaded', function() {
    const COMMENT_MIN = 2;
    const COMMENT_MAX = 500;
    // Carrega os comentários para cada post
    const commentContainers = document.querySelectorAll('.comments-container');
    commentContainers.forEach(container => {
        const postId = container.dataset.postId;
        loadComments(postId);
    });
    
    // Configura os formulários de comentários
    const commentForms = document.querySelectorAll('.comment-form');
    commentForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const postId = this.dataset.postId;
            const textarea = this.querySelector('textarea');
            const commentText = textarea.value.trim();
            
            if (!commentText) {
                alert('Escreva uma resposta antes de enviar.');
                return;
            }
            if (commentText.length < COMMENT_MIN || commentText.length > COMMENT_MAX) {
                alert(`Sua resposta precisa ter entre ${COMMENT_MIN} e ${COMMENT_MAX} caracteres.`);
                return;
            }
            if (commentText) {
                submitComment(postId, commentText, textarea);
            }
        });
    });
});

/**
 * Carrega os comentários para um post específico
 * @param {string} postId - ID do post
 */
function loadComments(postId) {
    fetch(`/api/comments/${postId}`)
        .then(response => response.json())
        .then(data => {
            const container = document.querySelector(`.comments-container[data-post-id="${postId}"]`);
            
            if (data.comments && data.comments.length > 0) {
                container.innerHTML = '';
                
                data.comments.forEach(comment => {
                    container.appendChild(createCommentElement(comment));
                });
            } else {
                container.innerHTML = '<p class="text-sm" style="color:var(--text-muted)">Nenhuma resposta ainda. Talvez a sua seja a primeira.</p>';
            }
        })
        .catch(error => {
            console.error('Erro ao carregar comentários:', error);
            const container = document.querySelector(`.comments-container[data-post-id="${postId}"]`);
            container.innerHTML = '<p class="text-sm" style="color:var(--danger)">Não conseguimos carregar as respostas agora. Tente de novo em instantes.</p>';
        });
}

/**
 * Envia um novo comentário
 * @param {string} postId - ID do post
 * @param {string} commentText - Texto do comentário
 * @param {HTMLElement} textarea - Elemento textarea para limpar após envio
 */
function submitComment(postId, commentText, textarea) {
    if (window.EL_AUTH === false) {
        if (window.elRequireAuth) window.elRequireAuth('responder');
        return;
    }
    // Desabilita o textarea durante o envio
    textarea.disabled = true;
    const originalPlaceholder = textarea.placeholder;
    textarea.placeholder = 'Enviando resposta...';
    
    const payload = { text: commentText };
    fetch(`/api/comments/${postId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    })
        .then(async response => {
            const data = await response.json().catch(() => ({}));
            if (!response.ok || data.error) {
                if (data.auth_required && window.elRequireAuth) { window.elRequireAuth('responder'); }
                const err = new Error(data.error || 'Não conseguimos enviar sua resposta agora.');
                err.detail = data.detail; err.context = data.context; err.status = response.status;
                throw err;
            }
            return data;
        })
        .then(data => {

            if (data.comment) {
                const container = document.querySelector(`.comments-container[data-post-id="${postId}"]`);
                
                // Se for o primeiro comentário, limpa a mensagem "nenhum comentário"
                if (container.querySelector('p.text-gray-500')) {
                    container.innerHTML = '';
                }
                
                // Adiciona o novo comentário
                const commentElement = createCommentElement(data.comment);
                commentElement.classList.add('comentario-novo');
                container.appendChild(commentElement);
                
                // Limpa o textarea
                textarea.value = '';
                
                // Scroll para o novo comentário
                commentElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                
                // Feedback visual de sucesso (no tom da marca)
                commentElement.style.boxShadow = '0 0 0 1px rgba(106,166,255,0.4)';
                setTimeout(() => {
                    commentElement.style.boxShadow = '';
                }, 1800);
            }
        })
        .catch(error => {
            // Log de debug detalhado pra achar a causa raiz (remover quando estável).
            console.error('COMMENT_ERROR', {
                postId: postId,
                payload: payload,
                status: error.status,
                serverError: error.message,
                detail: error.detail,
                context: error.context
            });
            alert(error.detail ? ('Erro real: ' + error.detail) : (error.message || 'Não conseguimos enviar sua resposta agora. Tente de novo em instantes.'));
        })
        .finally(() => {
            // Reabilita o textarea
            textarea.disabled = false;
            textarea.placeholder = originalPlaceholder;
        });
}

/**
 * Cria um elemento HTML para um comentário
 * @param {Object} comment - Dados do comentário
 * @returns {HTMLElement} - Elemento div do comentário
 */
function createCommentElement(comment) {
    const div = document.createElement('div');
    div.className = 'comentario-container';
    div.dataset.commentId = comment.id;
    div.style.cssText = 'border:1px solid var(--border);background:rgba(159,180,212,0.04);border-radius:14px;padding:0.9rem 1rem;';

    // Cabeçalho só aparece para respostas da equipe (cargo oficial). Usuário comum segue anônimo.
    let authorHeader = '';
    if (comment.author_role && comment.author_name) {
        authorHeader = `
            <div class="flex items-center gap-2 mb-1">
                <span class="text-sm font-medium" style="color:var(--text-main)">${escapeHTML(comment.author_name)}</span>
                <span class="role-tag role-tag--${escapeHTML(comment.author_role)}" title="Resposta da equipe EntreLinhas">
                    <span class="role-tag-dot" aria-hidden="true"></span>${escapeHTML(comment.author_role_label || 'Equipe')}
                </span>
            </div>`;
    }

    div.innerHTML = `
        <div class="flex justify-between items-start gap-3">
            <div class="flex-grow min-w-0">
                ${authorHeader}
                <p class="text-sm" style="color:var(--text)">${escapeHTML(comment.mensagem || comment.text)}</p>
                <div class="mt-2 text-xs" style="color:var(--text-faint)">${comment.data_comentario || comment.date}</div>
            </div>
            <button
                class="report-comment-button text-xs flex items-center transition duration-300 flex-shrink-0"
                style="color:var(--text-muted)"
                onmouseover="this.style.color='var(--danger)'" onmouseout="this.style.color='var(--text-muted)'"
                data-comment-id="${comment.id}"
                title="Denunciar esta resposta à moderação"
            >
                <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M3 6a3 3 0 013-3h10a1 1 0 01.8 1.6L14.25 8l2.55 3.4A1 1 0 0116 13H6a1 1 0 00-1 1v3a1 1 0 11-2 0V6z" clip-rule="evenodd" />
                </svg>
                Denunciar
            </button>
        </div>
    `;
    
    // Adiciona event listener para o botão de report
    const reportButton = div.querySelector('.report-comment-button');
    reportButton.addEventListener('click', function() {
        reportComment(comment.id);
    });
    
    return div;
}

/**
 * Escapa caracteres HTML para prevenir XSS
 * @param {string} unsafe - String não segura
 * @returns {string} - String escapada
 */
function escapeHTML(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/**
 * Reporta um comentário
 * @param {string} commentId - ID do comentário
 */
function reportComment(commentId) {
    if (confirm('Denunciar esta resposta à moderação?')) {
        fetch(`/api/report_comment/${commentId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ reason: 'Conteúdo inadequado' }),
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Denúncia enviada. A moderação vai olhar com cuidado.');

                    // Desabilita o botão para evitar denúncias repetidas
                    const reportButton = document.querySelector(`[data-comment-id="${commentId}"] .report-comment-button`);
                    if (reportButton) {
                        reportButton.disabled = true;
                        reportButton.textContent = 'Denunciado';
                        reportButton.classList.add('opacity-50', 'cursor-not-allowed');
                    }
                } else {
                    alert(data.message || 'Não conseguimos enviar seu aviso agora.');
                }
            })
            .catch(error => {
                console.error('Erro ao reportar comentário:', error);
                alert('Não conseguimos enviar seu aviso agora. Tente de novo em instantes.');
            });
    }
}
