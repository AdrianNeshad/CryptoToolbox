function updateNetStatus() {
    const el = document.getElementById('net-status');
    const text = document.getElementById('net-status-text');
    if (!el || !text) return;

    if (navigator.onLine) {
        text.textContent = 'Online';
        el.classList.remove('offline');
        el.classList.add('online');
    } else {
        text.textContent = 'Offline';
        el.classList.remove('online');
        el.classList.add('offline');
    }
}

window.addEventListener('online', updateNetStatus);
window.addEventListener('offline', updateNetStatus);
updateNetStatus();

function loadTool(item) {
    const frame = document.getElementById('tool-frame');
    const placeholder = document.getElementById('content-placeholder');
    if (!frame || !placeholder || !item) return;

    document.querySelectorAll('.nav-item.active').forEach((el) => el.classList.remove('active'));
    item.classList.add('active');

    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    const src = item.dataset.src;
    const separator = src.indexOf('?') === -1 ? '?' : '&';
    frame.src = src + separator + 'theme=' + theme;
    frame.style.display = 'block';
    placeholder.style.display = 'none';
}

function initToolNav() {
    document.querySelectorAll('.nav-item[data-type="frame"]').forEach((item) => {
        item.addEventListener('click', () => loadTool(item));
    });
}

initToolNav();

function initToolSearch() {
    const app = document.querySelector('.app');
    const search = document.getElementById('tool-search');
    const wrap = document.querySelector('.sidebar-search');
    const searchToggle = document.getElementById('search-toggle');
    const clearButton = document.getElementById('tool-search-clear');
    const emptyMessage = document.getElementById('nav-empty');
    if (!search || !wrap) return;

    const items = Array.from(document.querySelectorAll('.nav-item'));

    function itemText(item) {
        const title = item.querySelector('.nav-item-title');
        const desc = item.querySelector('.nav-item-desc');
        return ((title ? title.textContent : '') + ' ' + (desc ? desc.textContent : '')).toLowerCase();
    }

    function applyFilter(query) {
        const q = query.trim().toLowerCase();
        wrap.classList.toggle('has-value', q.length > 0);

        if (!q) {
            items.forEach((item) => item.classList.remove('search-hidden'));
            document.querySelectorAll('.nav-subgroup, .nav-group').forEach(
                (el) => el.classList.remove('search-hidden'));
            if (emptyMessage) emptyMessage.classList.add('display-none');
            return;
        }

        let anyVisible = false;
        items.forEach((item) => {
            const match = itemText(item).indexOf(q) !== -1;
            item.classList.toggle('search-hidden', !match);
            if (match) anyVisible = true;
        });

        // Collapse any subgroup / group that has no visible items left.
        document.querySelectorAll('.nav-subgroup').forEach((group) => {
            const hasVisible = group.querySelector('.nav-item:not(.search-hidden)');
            group.classList.toggle('search-hidden', !hasVisible);
        });
        document.querySelectorAll('.nav-group').forEach((group) => {
            const hasVisible = group.querySelector('.nav-item:not(.search-hidden)');
            group.classList.toggle('search-hidden', !hasVisible);
        });

        if (emptyMessage) emptyMessage.classList.toggle('display-none', anyVisible);
    }

    function openSearch() {
        if (app) app.classList.add('search-open');
        if (searchToggle) searchToggle.setAttribute('aria-expanded', 'true');
        // Wait for the expand transition to start before focusing so the
        // field is visible when it receives focus.
        setTimeout(() => search.focus(), 0);
    }

    function closeSearch() {
        if (app) app.classList.remove('search-open');
        if (searchToggle) searchToggle.setAttribute('aria-expanded', 'false');
        search.value = '';
        applyFilter('');
        search.blur();
    }

    function toggleSearch() {
        if (app && app.classList.contains('search-open')) {
            closeSearch();
        } else {
            openSearch();
        }
    }

    if (searchToggle) {
        searchToggle.addEventListener('click', toggleSearch);
    }

    search.addEventListener('input', () => applyFilter(search.value));
    search.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeSearch();
        }
    });

    if (clearButton) {
        clearButton.addEventListener('click', () => {
            search.value = '';
            applyFilter('');
            search.focus();
        });
    }
}

initToolSearch();

function initSidebarToggle() {
    const app = document.querySelector('.app');
    const toggle = document.getElementById('sidebar-toggle');
    if (!app || !toggle) return;

    toggle.addEventListener('click', () => {
        app.classList.toggle('sidebar-collapsed');
    });
}

initSidebarToggle();

function initThemeToggle() {
    const THEME_KEY = 'theme';
    const toggle = document.getElementById('theme-toggle');
    const frame = document.getElementById('tool-frame');
    if (!toggle) return;

    function getStoredTheme() {
        try {
            const saved = localStorage.getItem(THEME_KEY);
            return (saved === 'light' || saved === 'dark') ? saved : 'dark';
        } catch (e) {
            return 'dark';
        }
    }

    function setStoredTheme(value) {
        try {
            localStorage.setItem(THEME_KEY, value);
        } catch (e) {
            /* localStorage unavailable (e.g. private mode) — the theme still applies for the session */
        }
    }

    function broadcastTheme(value) {
        if (frame && frame.contentWindow) {
            try {
                frame.contentWindow.postMessage({ source: 'cryptotoolbox', type: 'theme', theme: value }, '*');
            } catch (e) {
                /* the tool could not be reached (e.g. still loading) — ignore */
            }
        }
    }

    function applyTheme(value) {
        document.documentElement.setAttribute('data-theme', value);
        toggle.setAttribute('aria-checked', value === 'light' ? 'true' : 'false');
    }

    let theme = getStoredTheme();
    applyTheme(theme);

    toggle.addEventListener('click', () => {
        theme = theme === 'dark' ? 'light' : 'dark';
        applyTheme(theme);
        setStoredTheme(theme);
        broadcastTheme(theme);
    });

    // If a tool is reloaded (e.g. via a click in the sidebar) — make sure it gets
    // the correct theme immediately, complementing the ?theme= in the src URL.
    if (frame) {
        frame.addEventListener('load', () => broadcastTheme(theme));
    }
}

initThemeToggle();

function initDownloadConfirm() {
    const modal = document.getElementById('download-modal');
    const text = document.getElementById('download-modal-text');
    const cancelButton = document.getElementById('download-modal-cancel');
    const confirmButton = document.getElementById('download-modal-confirm');
    if (!modal || !text || !cancelButton || !confirmButton) return;

    let pendingHref = null;

    function openModal(link) {
        pendingHref = link.href;
        const title = link.querySelector('.nav-item-title')?.textContent.trim() || 'the file';
        text.textContent = `Do you want to download "${title}" as a .zip file from GitHub?`;
        modal.classList.remove('display-none');
    }

    function closeModal() {
        modal.classList.add('display-none');
        pendingHref = null;
    }

    // Only real link downloads (<a href>) should show the confirmation modal.
    // Download entries that now open an info page are handled by initToolNav (data-type="frame").
    document.querySelectorAll('a.nav-item--download[href]').forEach((link) => {
        link.addEventListener('click', (event) => {
            event.preventDefault();
            openModal(link);
        });
    });

    cancelButton.addEventListener('click', closeModal);

    modal.addEventListener('click', (event) => {
        if (event.target === modal) closeModal();
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && !modal.classList.contains('display-none')) closeModal();
    });

    confirmButton.addEventListener('click', () => {
        if (pendingHref) {
            const link = document.createElement('a');
            link.href = pendingHref;
            link.download = '';
            document.body.appendChild(link);
            link.click();
            link.remove();
        }
        closeModal();
    });
}

initDownloadConfirm();

function initExternalLinkConfirm() {
    const modal = document.getElementById('external-link-modal');
    const text = document.getElementById('external-link-modal-text');
    const cancelButton = document.getElementById('external-link-modal-cancel');
    const confirmButton = document.getElementById('external-link-modal-confirm');
    if (!modal || !text || !cancelButton || !confirmButton) return;

    let pendingHref = null;

    function openModal(link) {
        pendingHref = link.href;
        const title = link.querySelector('.nav-item-title')?.textContent.trim() || 'the website';
        text.textContent = `Do you want to leave CryptoToolbox and open "${title}" in a new tab?`;
        modal.classList.remove('display-none');
    }

    function closeModal() {
        modal.classList.add('display-none');
        pendingHref = null;
    }

    document.querySelectorAll('.nav-item--link').forEach((link) => {
        link.addEventListener('click', (event) => {
            event.preventDefault();
            openModal(link);
        });
    });

    cancelButton.addEventListener('click', closeModal);

    modal.addEventListener('click', (event) => {
        if (event.target === modal) closeModal();
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && !modal.classList.contains('display-none')) closeModal();
    });

    confirmButton.addEventListener('click', () => {
        if (pendingHref) {
            window.open(pendingHref, '_blank', 'noopener,noreferrer');
        }
        closeModal();
    });
}

initExternalLinkConfirm();