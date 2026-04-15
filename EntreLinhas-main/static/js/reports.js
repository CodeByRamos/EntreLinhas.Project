// Arquivo JavaScript para gerenciar reports de posts

document.addEventListener('DOMContentLoaded', function() {
    // Adicionar event listeners para botões de report
    const reportButtons = document.querySelectorAll('.report-button');
    
    reportButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const postId = this.getAttribute('data-post-id');
            reportPost(postId, this);
        });
    });
});

function reportPost(postId, buttonElement) {
    // Confirmar ação com o usuário
    if (!confirm('Tem certeza que deseja reportar este desabafo? Esta ação não pode ser desfeita.')) {
        return;
    }
    
    // Desabilitar o botão temporariamente
    buttonElement.disabled = true;
    buttonElement.innerHTML = '<span class="loading-spinner"></span> Reportando...';
    
    // Fazer a requisição para reportar o post
    fetch('/api/report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            post_id: postId
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Mostrar mensagem de sucesso
            showNotification(data.message, 'success');
            
            // Atualizar o botão
            buttonElement.innerHTML = '✓ Reportado';
            buttonElement.classList.add('reported');
            buttonElement.disabled = true;
            
            // Se o post foi ocultado (5+ reports), remover do feed
            if (data.report_count >= 5) {
                const postElement = buttonElement.closest('.post-container');
                if (postElement) {
                    postElement.style.transition = 'opacity 0.5s ease';
                    postElement.style.opacity = '0';
                    setTimeout(() => {
                        postElement.remove();
                        showNotification('O desabafo foi removido devido ao número de reports.', 'info');
                    }, 500);
                }
            }
        } else {
            // Mostrar mensagem de erro
            showNotification(data.message, 'error');
            
            // Reabilitar o botão
            buttonElement.disabled = false;
            buttonElement.innerHTML = '🚩 Reportar';
        }
    })
    .catch(error => {
        console.error('Erro ao reportar post:', error);
        showNotification('Erro ao reportar o desabafo. Tente novamente.', 'error');
        
        // Reabilitar o botão
        buttonElement.disabled = false;
        buttonElement.innerHTML = '🚩 Reportar';
    });
}

function showNotification(message, type) {
    // Criar elemento de notificação
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-message">${message}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;
    
    // Adicionar estilos inline para a notificação
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        max-width: 400px;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        animation: slideIn 0.3s ease;
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
    
    // Remover automaticamente após 5 segundos
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }
    }, 5000);
}

// Adicionar estilos CSS para as animações
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    .loading-spinner {
        display: inline-block;
        width: 12px;
        height: 12px;
        border: 2px solid #ffffff;
        border-radius: 50%;
        border-top-color: transparent;
        animation: spin 1s ease-in-out infinite;
    }
    
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
    
    .report-button.reported {
        background-color: #6b7280 !important;
        cursor: not-allowed !important;
    }
    
    .notification-content {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .notification-close {
        background: none;
        border: none;
        color: inherit;
        font-size: 18px;
        cursor: pointer;
        margin-left: 10px;
    }
`;
document.head.appendChild(style);

