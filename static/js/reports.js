document.addEventListener('DOMContentLoaded', function() {
    ensureReportModal();
    document.querySelectorAll('.report-button').forEach((button) => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            openReportModal(this.dataset.postId, this);
        });
    });
});

const reportReasons = [
    ['ofensivo', 'Conteudo ofensivo'],
    ['odio', 'Discurso de odio'],
    ['assedio', 'Assedio'],
    ['perigoso', 'Conteudo perigoso'],
    ['spam', 'Spam'],
    ['exposicao', 'Exposicao pessoal'],
    ['outro', 'Outro'],
];

let currentReportButton = null;

function ensureReportModal() {
    if (document.getElementById('report-modal')) return;
    const modal = document.createElement('div');
    modal.id = 'report-modal';
    modal.className = 'report-modal hidden';
    modal.innerHTML = `
        <div class="modal-backdrop absolute inset-0"></div>
        <form class="report-modal-card" id="report-form">
            <input type="hidden" id="report-post-id" />
            <h3>Avisar a moderação</h3>
            <p>Use este aviso quando algo ferir o cuidado do EntreLinhas. A pessoa do outro lado continua sendo tratada com respeito.</p>
            <label for="report-reason">Motivo</label>
            <select id="report-reason" class="input-modern" required>
                ${reportReasons.map(([value, label]) => `<option value="${value}">${label}</option>`).join('')}
            </select>
            <label for="report-details">Detalhes, se quiser</label>
            <textarea id="report-details" class="input-modern" maxlength="500" rows="3" placeholder="O que a moderação precisa saber?"></textarea>
            <div class="report-modal-actions">
                <button type="button" class="btn-modern btn-ghost" id="report-cancel">Voltar</button>
                <button type="submit" class="btn-modern btn-primary">Enviar aviso</button>
            </div>
        </form>
    `;
    document.body.appendChild(modal);
    document.getElementById('report-cancel').addEventListener('click', closeReportModal);
    document.getElementById('report-form').addEventListener('submit', submitReport);
}

function openReportModal(postId, button) {
    currentReportButton = button;
    document.getElementById('report-post-id').value = postId;
    document.getElementById('report-details').value = '';
    const modal = document.getElementById('report-modal');
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeReportModal() {
    const modal = document.getElementById('report-modal');
    modal.classList.add('hidden');
    modal.classList.remove('flex');
}

function submitReport(event) {
    event.preventDefault();
    const postId = document.getElementById('report-post-id').value;
    const reason = document.getElementById('report-reason').value;
    const details = document.getElementById('report-details').value.trim();
    const button = currentReportButton;
    const submitButton = event.target.querySelector('button[type="submit"]');
    submitButton.disabled = true;

    fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ post_id: postId, reason, details })
    })
        .then(async (response) => {
            const data = await response.json();
            if (!response.ok) throw data;
            return data;
        })
        .then((data) => {
            closeReportModal();
            showSoftNotice(data.message || 'A moderação recebeu seu aviso.');
            if (button) {
                button.textContent = 'Avisado';
                button.disabled = true;
                button.classList.add('reported');
            }
            if (data.report_count >= 5) {
                const postElement = button ? button.closest('article.post-card') : null;
                if (postElement) {
                    postElement.style.opacity = '0';
                    setTimeout(() => postElement.remove(), 450);
                }
            }
        })
        .catch((data) => {
            showSoftNotice((data && data.message) || 'Não conseguimos enviar seu aviso agora.', 'error');
        })
        .finally(() => {
            submitButton.disabled = false;
        });
}
