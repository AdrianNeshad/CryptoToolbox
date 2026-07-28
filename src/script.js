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