// Reações do EntreLinhas — ícones de linha (sem emoji), no tom calmo da marca.

// Ícones SVG: herdam a cor do botão via currentColor.
const REACAO_ICONS = {
  // Empatia — balão de fala com um coração dentro ("te entendo")
  empathy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.9 20A9 9 0 1 0 4 16.1L2 22z"/><path d="M15.8 9.2a2.5 2.5 0 0 0-3.5 0l-.3.3-.3-.3a2.5 2.5 0 0 0-3.4 3.6l3.7 3.6 3.8-3.6c1-1 1-2.6 0-3.6z"/></svg>',
  // Força — broto crescendo ("força pra seguir")
  sprout: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 20h10"/><path d="M10 20c5.5-2.5.8-6.4 3-10"/><path d="M9.5 9.4c1.1.8 1.8 2.2 2.3 3.7-2 .4-3.5.4-4.8-.3-1.2-.6-2.3-1.9-3-4.2 2.8-.5 4.4 0 5.5.8z"/><path d="M14.1 6a7 7 0 0 0-1.1 4c1.9-.1 3.3-.6 4.3-1.4 1-1 1.6-2.3 1.7-4.6-2.7.1-4 1-4.9 2z"/></svg>',
  // Abraço — mãos amparando um coração ("abraço virtual")
  embrace: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 14c1.5-1.5 3-3.2 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.8 0-3 .5-4.5 2-1.5-1.5-2.7-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4 3 5.5l7 7z"/><path d="M12 5 9 8a2.2 2.2 0 0 0 0 3.1c.8.8 2.1.8 3 0l2-1.9a2.8 2.8 0 0 1 3.8 0l3 2.7"/><path d="m18 15-2-2"/><path d="m15 18-2-2"/></svg>',
  // Inspiração — brilho ("me inspirou")
  spark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l1.6 5.3a2 2 0 0 0 1.3 1.3L20 11l-5.1 1.4a2 2 0 0 0-1.3 1.3L12 19l-1.6-5.3a2 2 0 0 0-1.3-1.3L4 11l5.1-1.4a2 2 0 0 0 1.3-1.3z"/><path d="M19 4v3"/><path d="M20.5 5.5h-3"/></svg>'
};

// Fonte única: config.py REACOES, injetado em window.EL_REACOES pelo base.html.
// O fallback abaixo só é usado se o global não estiver presente.
const REACOES_CONFIG = (window.EL_REACOES && window.EL_REACOES.length)
  ? window.EL_REACOES
  : [
      { valor: 'te_entendo', nome: 'Te entendo', icon: 'empathy' },
      { valor: 'forca', nome: 'Força', icon: 'sprout' },
      { valor: 'abraco', nome: 'Abraço', icon: 'embrace' },
      { valor: 'inspirador', nome: 'Me inspirou', icon: 'spark' }
    ];

document.addEventListener('DOMContentLoaded', function () {
  const reactionContainers = document.querySelectorAll('[data-post-id]');
  reactionContainers.forEach(container => {
    if (container.classList.contains('reaction-buttons-container') ||
        container.querySelector('.reaction-buttons-container')) {
      loadReactions(container.dataset.postId);
    }
  });
});

/** Carrega as reações de um post. */
function loadReactions(postId) {
  fetch(`/api/reactions/${postId}`)
    .then(response => {
      if (!response.ok) throw new Error('Não conseguimos carregar as reações agora.');
      return response.json();
    })
    .then(data => {
      const container = document.querySelector(`[data-post-id="${postId}"] .reaction-buttons-container`);
      if (!container) return;
      container.innerHTML = '';
      REACOES_CONFIG.forEach(reacao => {
        const count = (data.reactions && data.reactions[reacao.valor]) || 0;
        container.appendChild(createReactionButton(reacao, count, postId));
      });
    })
    .catch(error => {
      console.error('Erro ao carregar reações:', error);
      const container = document.querySelector(`[data-post-id="${postId}"] .reaction-buttons-container`);
      if (container) {
        container.innerHTML = '<span class="text-sm" style="color:var(--text-muted)">Não conseguimos carregar as reações agora.</span>';
      }
    });
}

/** Cria um botão de reação com ícone de linha. */
function createReactionButton(reacao, count, postId) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'reaction-button reacao-botao';
  button.dataset.reacao = reacao.valor;
  button.dataset.postId = postId;
  button.title = reacao.nome;
  button.setAttribute('aria-label', `${reacao.nome} (${count})`);
  button.innerHTML =
    `<span class="reacao-icon" aria-hidden="true">${REACAO_ICONS[reacao.icon] || ''}</span>` +
    `<span class="reacao-count">${count}</span>`;
  button.addEventListener('click', () => toggleReaction(postId, reacao.valor));
  return button;
}

/** Alterna (adiciona/remove) uma reação. */
function toggleReaction(postId, reactionType) {
  let userId = localStorage.getItem('user_id');
  if (!userId) {
    userId = 'user_' + Math.random().toString(36).substr(2, 9);
    localStorage.setItem('user_id', userId);
  }

  const button = document.querySelector(`button[data-reacao="${reactionType}"][data-post-id="${postId}"]`);
  if (button) {
    button.disabled = true;
    button.style.opacity = '0.7';
  }

  fetch(`/api/reactions/${postId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: reactionType, user_id: userId })
  })
    .then(response => {
      if (!response.ok) throw new Error('Não conseguimos registrar sua reação agora.');
      return response.json();
    })
    .then(data => {
      if (!data.reactions) return;
      Object.entries(data.reactions).forEach(([tipo, contagem]) => {
        const btn = document.querySelector(`button[data-reacao="${tipo}"][data-post-id="${postId}"]`);
        if (!btn) return;
        const countSpan = btn.querySelector('.reacao-count');
        if (countSpan) countSpan.textContent = contagem;
        if (tipo === reactionType) {
          if (data.action === 'added') {
            btn.classList.add('active');
            btn.style.transform = 'scale(1.08)';
            setTimeout(() => { btn.style.transform = 'scale(1)'; }, 200);
          } else if (data.action === 'removed') {
            btn.classList.remove('active');
          }
        }
      });
      showReactionFeedback(postId, data.action === 'added' ? 'Sua reação ficou registrada.' : 'Sua reação foi retirada.');
    })
    .catch(error => {
      console.error('Erro ao processar reação:', error);
      showReactionFeedback(postId, 'Não conseguimos acolher sua reação agora. Tente de novo em instantes.', 'error');
    })
    .finally(() => {
      if (button) {
        button.disabled = false;
        button.style.opacity = '1';
      }
    });
}

/** Feedback breve abaixo das reações. */
function showReactionFeedback(postId, message, type = 'success') {
  const container = document.querySelector(`[data-post-id="${postId}"] .reaction-buttons-container`);
  if (!container) return;

  const existingFeedback = container.querySelector('.reaction-feedback');
  if (existingFeedback) existingFeedback.remove();

  const feedback = document.createElement('div');
  feedback.className = 'reaction-feedback text-xs mt-2 w-full transition-all duration-300';
  feedback.style.color = type === 'error' ? 'var(--danger)' : 'var(--accent)';
  feedback.textContent = message;
  container.appendChild(feedback);

  setTimeout(() => {
    if (feedback.parentNode) {
      feedback.style.opacity = '0';
      setTimeout(() => feedback.remove(), 300);
    }
  }, 3000);
}
