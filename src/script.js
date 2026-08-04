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

function initToolNav() {
    const frame = document.getElementById('tool-frame');
    const placeholder = document.getElementById('content-placeholder');
    if (!frame || !placeholder) return;

    document.querySelectorAll('.nav-item[data-type="frame"]').forEach((item) => {
        item.addEventListener('click', () => {
            document.querySelectorAll('.nav-item.active').forEach((el) => el.classList.remove('active'));
            item.classList.add('active');

            frame.src = item.dataset.src;
            frame.style.display = 'block';
            placeholder.style.display = 'none';
        });
    });
}

initToolNav();

function initSidebarToggle() {
    const app = document.querySelector('.app');
    const toggle = document.getElementById('sidebar-toggle');
    if (!app || !toggle) return;

    toggle.addEventListener('click', () => {
        app.classList.toggle('sidebar-collapsed');
    });
}

initSidebarToggle();

function initDownloadConfirm() {
    const modal = document.getElementById('download-modal');
    const text = document.getElementById('download-modal-text');
    const cancelButton = document.getElementById('download-modal-cancel');
    const confirmButton = document.getElementById('download-modal-confirm');
    if (!modal || !text || !cancelButton || !confirmButton) return;

    let pendingHref = null;

    function openModal(link) {
        pendingHref = link.href;
        const title = link.querySelector('.nav-item-title')?.textContent.trim() || 'filen';
        text.textContent = `Vill du ladda ner "${title}" som .zip-fil från GitHub?`;
        modal.classList.remove('display-none');
    }

    function closeModal() {
        modal.classList.add('display-none');
        pendingHref = null;
    }

    document.querySelectorAll('.nav-item--download').forEach((link) => {
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
        const title = link.querySelector('.nav-item-title')?.textContent.trim() || 'webbplatsen';
        text.textContent = `Vill du lämna Verktygslådan och öppna "${title}" i ny flik?`;
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