function updateNetStatus() {
    const el = document.getElementById('net-status');
    const text = document.getElementById('net-status-text');
    const slash = document.getElementById('net-status-slash');
    if (!el || !text || !slash) return;

    if (navigator.onLine) {
        text.textContent = 'Online';
        slash.style.display = 'none';
        el.classList.remove('offline');
        el.classList.add('online');
    } else {
        text.textContent = 'Offline';
        slash.style.display = 'block';
        el.classList.remove('online');
        el.classList.add('offline');
    }
}

window.addEventListener('online', updateNetStatus);
window.addEventListener('offline', updateNetStatus);
updateNetStatus();