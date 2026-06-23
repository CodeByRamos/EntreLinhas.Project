// Dropdowns premium do EntreLinhas — aprimora <select class="input-modern">
// com um listbox estilizado e animado, mantendo o <select> nativo para o envio
// do formulário e como base de acessibilidade (role=listbox + aria-activedescendant).
(function () {
  let idSeq = 0;

  function enhance(select) {
    if (select.dataset.elEnhanced || select.multiple) return;
    select.dataset.elEnhanced = '1';
    const uid = 'elsel-' + (idSeq++);

    const wrap = document.createElement('div');
    wrap.className = 'el-select';
    select.parentNode.insertBefore(wrap, select);
    wrap.appendChild(select);
    select.classList.add('el-select-native');
    select.setAttribute('tabindex', '-1');
    select.setAttribute('aria-hidden', 'true');

    // Botão acessível
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'el-select-button input-modern';
    button.id = uid + '-btn';
    button.setAttribute('aria-haspopup', 'listbox');
    button.setAttribute('aria-expanded', 'false');
    if (select.getAttribute('aria-label')) button.setAttribute('aria-label', select.getAttribute('aria-label'));
    const label = document.createElement('span');
    label.className = 'el-select-label';
    button.appendChild(label);
    const chev = document.createElement('span');
    chev.className = 'el-select-chevron';
    chev.setAttribute('aria-hidden', 'true');
    chev.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>';
    button.appendChild(chev);
    wrap.appendChild(button);

    // Painel (listbox)
    const panel = document.createElement('div');
    panel.className = 'el-select-panel';
    panel.setAttribute('role', 'listbox');
    panel.id = uid + '-list';
    wrap.appendChild(panel);

    let optionEls = [];
    let activeIndex = -1;

    function buildOptions() {
      panel.innerHTML = '';
      optionEls = Array.from(select.options).map((opt, i) => {
        const el = document.createElement('div');
        el.className = 'el-select-option';
        el.id = uid + '-opt-' + i;
        el.setAttribute('role', 'option');
        el.dataset.index = i;
        el.textContent = opt.textContent;
        if (opt.disabled) el.classList.add('is-disabled');
        el.addEventListener('click', function () {
          if (opt.disabled) return;
          choose(i);
        });
        el.addEventListener('mousemove', function () { setActive(i); });
        panel.appendChild(el);
        return el;
      });
    }

    function sync() {
      const sel = select.options[select.selectedIndex];
      label.textContent = sel ? sel.textContent : '';
      label.classList.toggle('is-placeholder', !!(sel && sel.disabled));
      optionEls.forEach((el, i) => {
        const on = i === select.selectedIndex;
        el.classList.toggle('is-selected', on);
        el.setAttribute('aria-selected', on ? 'true' : 'false');
      });
    }

    function choose(i) {
      select.selectedIndex = i;
      select.dispatchEvent(new Event('change', { bubbles: true }));
      sync();
      close();
      button.focus();
    }

    function setActive(i) {
      activeIndex = i;
      optionEls.forEach((el, idx) => el.classList.toggle('is-active', idx === i));
      if (optionEls[i]) {
        button.setAttribute('aria-activedescendant', optionEls[i].id);
        optionEls[i].scrollIntoView({ block: 'nearest' });
      }
    }

    function move(dir) {
      let i = activeIndex;
      for (let n = 0; n < optionEls.length; n++) {
        i = (i + dir + optionEls.length) % optionEls.length;
        if (!select.options[i].disabled) { setActive(i); return; }
      }
    }

    let open = false;
    function openPanel() {
      if (open) return;
      open = true;
      buildOptions();
      sync();
      wrap.classList.add('is-open');
      button.setAttribute('aria-expanded', 'true');
      button.setAttribute('aria-controls', panel.id);
      setActive(select.selectedIndex >= 0 ? select.selectedIndex : 0);
    }
    function close() {
      if (!open) return;
      open = false;
      wrap.classList.remove('is-open');
      button.setAttribute('aria-expanded', 'false');
      button.removeAttribute('aria-activedescendant');
    }

    button.addEventListener('click', function () { open ? close() : openPanel(); });
    button.addEventListener('keydown', function (e) {
      switch (e.key) {
        case 'ArrowDown': e.preventDefault(); open ? move(1) : openPanel(); break;
        case 'ArrowUp': e.preventDefault(); open ? move(-1) : openPanel(); break;
        case 'Home': if (open) { e.preventDefault(); setActive(0); } break;
        case 'End': if (open) { e.preventDefault(); setActive(optionEls.length - 1); } break;
        case 'Enter':
        case ' ':
          e.preventDefault();
          if (open && activeIndex >= 0) choose(activeIndex); else openPanel();
          break;
        case 'Escape': if (open) { e.preventDefault(); close(); } break;
        case 'Tab': close(); break;
      }
    });
    document.addEventListener('click', function (e) { if (!wrap.contains(e.target)) close(); });
    // Se algum código mudar o select por fora, reflete no rótulo.
    select.addEventListener('change', sync);

    buildOptions();
    sync();
  }

  function init(root) {
    (root || document).querySelectorAll('select.input-modern').forEach(enhance);
  }
  if (document.readyState !== 'loading') init();
  else document.addEventListener('DOMContentLoaded', function () { init(); });
  window.elEnhanceSelects = init;
})();
