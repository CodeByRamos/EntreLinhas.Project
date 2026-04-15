// Arquivo JavaScript para gerenciar karma de comentários

document.addEventListener('DOMContentLoaded', function() {
    // Carregar karma para todos os comentários visíveis
    loadAllCommentKarma();
    
    // Adicionar event listeners para botões de karma
    document.addEventListener('click', function(e) {
        if (e.target.closest('.karma-button')) {
            e.preventDefault();
            
            const button = e.target.closest('.karma-button');
            const commentId = button.getAttribute('data-comment-id');
            const karmaType = button.getAttribute('data-karma-type');
            
            voteCommentKarma(commentId, karmaType, button);
        }
    });
});

function loadAllCommentKarma() {
    const commentContainers = document.querySelectorAll('[data-comment-id]');
    
    commentContainers.forEach(container => {
        const commentId = container.getAttribute('data-comment-id');
        if (commentId) {
            loadCommentKarma(commentId);
        }
    });
}

function loadCommentKarma(commentId) {
    fetch(`/api/comment-karma/${commentId}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateKarmaDisplay(commentId, data);
            }
        })
        .catch(error => {
            console.error('Erro ao carregar karma do comentário:', error);
        });
}

function voteCommentKarma(commentId, karmaType, buttonElement) {
    // Desabilitar botões temporariamente
    const karmaContainer = buttonElement.closest('.karma-container');
    const buttons = karmaContainer.querySelectorAll('.karma-button');
    buttons.forEach(btn => btn.disabled = true);
    
    // Fazer a requisição para votar
    fetch('/api/comment-karma', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            comment_id: commentId,
            karma_type: karmaType
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Atualizar a exibição do karma
            updateKarmaDisplay(commentId, data);
            
            // Mostrar notificação de sucesso
            if (data.action === 'added') {
                showKarmaNotification(`Voto ${karmaType === 'up' ? 'positivo' : 'negativo'} adicionado!`, 'success');
            } else {
                showKarmaNotification('Voto removido!', 'info');
            }
            
            // Verificar se o comentário atingiu karma alto
            if (data.score >= 10) {
                markAsHighKarma(commentId);
            } else {
                unmarkAsHighKarma(commentId);
            }
        } else {
            showKarmaNotification(data.message, 'error');
        }
        
        // Reabilitar botões
        buttons.forEach(btn => btn.disabled = false);
    })
    .catch(error => {
        console.error('Erro ao votar no karma:', error);
        showKarmaNotification('Erro ao votar. Tente novamente.', 'error');
        
        // Reabilitar botões
        buttons.forEach(btn => btn.disabled = false);
    });
}

function updateKarmaDisplay(commentId, data) {
    const karmaContainer = document.querySelector(`[data-comment-id="${commentId}"] .karma-container`);
    if (!karmaContainer) return;
    
    // Atualizar contadores
    const upButton = karmaContainer.querySelector('[data-karma-type="up"]');
    const downButton = karmaContainer.querySelector('[data-karma-type="down"]');
    const scoreElement = karmaContainer.querySelector('.karma-score');
    
    if (upButton) {
        const upCount = upButton.querySelector('.karma-count');
        if (upCount) upCount.textContent = data.up_votes;
        
        // Atualizar estado visual do botão
        if (data.user_karma === 'up') {
            upButton.classList.add('active', 'text-green-600', 'bg-green-100');
            upButton.classList.remove('text-gray-500', 'hover:text-green-600');
        } else {
            upButton.classList.remove('active', 'text-green-600', 'bg-green-100');
            upButton.classList.add('text-gray-500', 'hover:text-green-600');
        }
    }
    
    if (downButton) {
        const downCount = downButton.querySelector('.karma-count');
        if (downCount) downCount.textContent = data.down_votes;
        
        // Atualizar estado visual do botão
        if (data.user_karma === 'down') {
            downButton.classList.add('active', 'text-red-600', 'bg-red-100');
            downButton.classList.remove('text-gray-500', 'hover:text-red-600');
        } else {
            downButton.classList.remove('active', 'text-red-600', 'bg-red-100');
            downButton.classList.add('text-gray-500', 'hover:text-red-600');
        }
    }
    
    if (scoreElement) {
        scoreElement.textContent = data.score;
        
        // Atualizar cor do score baseado no valor
        scoreElement.classList.remove('text-green-600', 'text-red-600', 'text-gray-600');
        if (data.score > 0) {
            scoreElement.classList.add('text-green-600');
        } else if (data.score < 0) {
            scoreElement.classList.add('text-red-600');
        } else {
            scoreElement.classList.add('text-gray-600');
        }
    }
}

function markAsHighKarma(commentId) {
    const commentElement = document.querySelector(`[data-comment-id="${commentId}"]`);
    if (!commentElement) return;
    
    // Adicionar badge de "apoio confiável"
    let badge = commentElement.querySelector('.high-karma-badge');
    if (!badge) {
        badge = document.createElement('div');
        badge.className = 'high-karma-badge inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 ml-2';
        badge.innerHTML = '⭐ Apoio Confiável';
        
        const commentHeader = commentElement.querySelector('.comment-header');
        if (commentHeader) {
            commentHeader.appendChild(badge);
        }
    }
    
    // Adicionar destaque visual ao comentário
    commentElement.classList.add('high-karma-comment');
    commentElement.style.borderLeft = '4px solid #f59e0b';
    commentElement.style.backgroundColor = 'rgba(251, 191, 36, 0.05)';
}

function unmarkAsHighKarma(commentId) {
    const commentElement = document.querySelector(`[data-comment-id="${commentId}"]`);
    if (!commentElement) return;
    
    // Remover badge de "apoio confiável"
    const badge = commentElement.querySelector('.high-karma-badge');
    if (badge) {
        badge.remove();
    }
    
    // Remover destaque visual
    commentElement.classList.remove('high-karma-comment');
    commentElement.style.borderLeft = '';
    commentElement.style.backgroundColor = '';
}

function showKarmaNotification(message, type) {
    // Criar elemento de notificação
    const notification = document.createElement('div');
    notification.className = `karma-notification karma-notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-message">${message}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;
    
    // Adicionar estilos inline para a notificação
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        z-index: 1000;
        max-width: 300px;
        padding: 12px;
        border-radius: 6px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        animation: slideInKarma 0.3s ease;
        font-size: 14px;
    `;
    
    // Definir cores baseadas no tipo
    if (type === 'success') {
        notification.style.backgroundColor = '#10b981';
        notification.style.color = 'white';
    } else if (type === 'error') {
        notification.style.backgroundColor = '#ef4444';
        notification.style.color = 'white';
    } else if (type === 'info') {
        notification.style.backgroundColor = '#3b82f6';
        notification.style.color = 'white';
    }
    
    // Adicionar ao DOM
    document.body.appendChild(notification);
    
    // Remover automaticamente após 3 segundos
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.animation = 'slideOutKarma 0.3s ease';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }
    }, 3000);
}

// Adicionar estilos CSS para as animações
const karmaStyle = document.createElement('style');
karmaStyle.textContent = `
    @keyframes slideInKarma {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutKarma {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    .karma-button {
        transition: all 0.2s ease;
    }
    
    .karma-button:hover {
        transform: scale(1.05);
    }
    
    .karma-button.active {
        transform: scale(1.1);
    }
    
    .karma-button:disabled {
        opacity: 0.6;
        cursor: not-allowed;
        transform: none !important;
    }
    
    .high-karma-comment {
        transition: all 0.3s ease;
    }
    
    .karma-container {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    .karma-score {
        font-weight: 600;
        min-width: 20px;
        text-align: center;
    }
`;
document.head.appendChild(karmaStyle);

