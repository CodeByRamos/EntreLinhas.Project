document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.echo-button').forEach((button) => {
        const postId = button.dataset.postId;
        loadEcho(button, postId);
        button.addEventListener('click', () => toggleEcho(button, postId));
    });
});

function updateEchoButton(button, state) {
    const label = button.querySelector('.echo-label');
    const count = button.querySelector('.echo-count');
    button.classList.toggle('is-active', Boolean(state.active));
    if (label) label.textContent = state.active ? 'Ecoado' : 'Ecoar';
    if (count) count.textContent = state.count || 0;
}

function loadEcho(button, postId) {
    fetch(`/api/echo/${postId}`)
        .then((response) => response.ok ? response.json() : null)
        .then((data) => {
            if (data && data.success) updateEchoButton(button, data.echo);
        })
        .catch(() => {});
}

function toggleEcho(button, postId) {
    button.disabled = true;
    fetch(`/api/echo/${postId}`, { method: 'POST' })
        .then(async (response) => {
            const data = await response.json();
            if (!response.ok) throw data;
            return data;
        })
        .then((data) => {
            updateEchoButton(button, { active: data.active, count: data.count });
            button.classList.add('echo-pop');
            setTimeout(() => button.classList.remove('echo-pop'), 300);
        })
        .catch((data) => {
            showSoftNotice((data && data.message) || 'Não conseguimos registrar seu eco agora.', 'error');
        })
        .finally(() => {
            button.disabled = false;
        });
}

function showSoftNotice(message, type = 'success') {
    const notice = document.createElement('div');
    notice.className = `soft-notice soft-notice-${type}`;
    notice.textContent = message;
    document.body.appendChild(notice);
    setTimeout(() => notice.classList.add('show'), 10);
    setTimeout(() => {
        notice.classList.remove('show');
        setTimeout(() => notice.remove(), 250);
    }, 3500);
}
