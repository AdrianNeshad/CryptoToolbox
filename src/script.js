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

// Each tool keeps its own iframe once it has been opened. Switching tools only
// hides/shows them, so whatever was typed in a tool survives until the window
// is closed or reloaded — nothing is stored.
const toolFrames = new Map();

function currentTheme() {
    return document.documentElement.getAttribute('data-theme') || 'dark';
}

function postTheme(frame, theme) {
    if (!frame.contentWindow) return;
    try {
        frame.contentWindow.postMessage({ source: 'cryptotoolbox', type: 'theme', theme: theme }, '*');
    } catch (e) {
        /* the tool could not be reached (e.g. still loading) — ignore */
    }
}

function createToolFrame(host, item) {
    const frame = document.createElement('iframe');
    const title = item.querySelector('.nav-item-title');
    const src = item.dataset.src;
    const separator = src.indexOf('?') === -1 ? '?' : '&';
    frame.className = 'tool-frame';
    frame.title = title ? title.textContent.trim() : 'Tool';
    frame.src = src + separator + 'theme=' + currentTheme();
    // Make sure the tool gets the correct theme as soon as it has loaded,
    // complementing the ?theme= in the src URL.
    frame.addEventListener('load', () => postTheme(frame, currentTheme()));
    host.appendChild(frame);
    toolFrames.set(src, frame);
    return frame;
}

function loadTool(item) {
    const host = document.getElementById('tool-host');
    const placeholder = document.getElementById('content-placeholder');
    if (!host || !placeholder || !item) return;

    document.querySelectorAll('.nav-item.active').forEach((el) => el.classList.remove('active'));
    item.classList.add('active');

    const frame = toolFrames.get(item.dataset.src) || createToolFrame(host, item);
    toolFrames.forEach((el) => el.classList.toggle('is-active', el === frame));
    host.hidden = false;
    placeholder.style.display = 'none';
}

// Some managed browsers (e.g. Edge with the IntranetFileLinksEnabled policy on Windows)
// block every file:// navigation a page starts itself — tool iframes as well as
// location.href. That can't be read from a web page, so instead a tiny probe page is
// loaded in a hidden iframe: if its message arrives, embedding works; if not, a popup
// tells the user how to open the tool themselves (only user-started navigations,
// such as "Open link in new tab" or pasting into the address bar, get through).
const FRAME_PROBE_SRC = 'src/frame-probe.html';
const FRAME_PROBE_TIMEOUT_MS = 2500;   // give up if the probe never answers (a local page loads in well under that)
const FRAME_PROBE_GRACE_MS = 500;      // after the probe's load event, wait this long for its message
const FRAME_PROBE_POLL_MS = 100;       // how often to look for Chromium's "about:blank#blocked" marker

let frameSupport = 'pending';          // 'pending' | 'ok' | 'blocked'
const frameSupportWaiters = [];

function whenFrameSupportKnown(callback) {
    if (frameSupport === 'pending') frameSupportWaiters.push(callback);
    else callback(frameSupport);
}

function initFrameProbe() {
    const probe = document.createElement('iframe');
    let graceTimer = null;

    function settle(result) {
        if (frameSupport !== 'pending') return;
        frameSupport = result;
        clearTimeout(timeoutTimer);
        clearTimeout(graceTimer);
        clearInterval(pollTimer);
        window.removeEventListener('message', onMessage);
        probe.remove();
        frameSupportWaiters.splice(0).forEach((callback) => callback(result));
    }

    function onMessage(event) {
        const data = event.data;
        if (event.source === probe.contentWindow && data &&
            data.source === 'cryptotoolbox' && data.type === 'frame-probe') {
            settle('ok');
        }
    }

    window.addEventListener('message', onMessage);
    const timeoutTimer = setTimeout(() => settle('blocked'), FRAME_PROBE_TIMEOUT_MS);
    probe.addEventListener('load', () => {
        if (frameSupport === 'pending' && !graceTimer) {
            graceTimer = setTimeout(() => settle('blocked'), FRAME_PROBE_GRACE_MS);
        }
    });
    // A blocked navigation leaves the frame on "about:blank#blocked", which (unlike a
    // loaded tool page) the parent may be able to read — settle right away if so.
    const pollTimer = setInterval(() => {
        try {
            if (String(probe.contentWindow.location.href).indexOf('#blocked') !== -1) settle('blocked');
        } catch (e) {
            /* not readable: the probe page itself has loaded — wait for its message */
        }
    }, FRAME_PROBE_POLL_MS);

    probe.hidden = true;
    probe.title = 'Frame support check';
    probe.setAttribute('aria-hidden', 'true');
    probe.tabIndex = -1;
    probe.src = FRAME_PROBE_SRC;
    document.body.appendChild(probe);
}

// Popup shown when tools can't be embedded. Navigating there from script is blocked too,
// so the popup gives the user a link to open in a new tab (right-click) and the address
// to paste into the address bar — both are navigations the browser itself starts.
function initFrameFallback() {
    const modal = document.getElementById('frame-fallback-modal');
    const text = document.getElementById('frame-fallback-modal-text');
    const link = document.getElementById('frame-fallback-modal-link');
    const address = document.getElementById('frame-fallback-modal-address');
    const status = document.getElementById('frame-fallback-modal-status');
    const closeButton = document.getElementById('frame-fallback-modal-close');
    const copyButton = document.getElementById('frame-fallback-modal-copy');
    if (!modal || !text || !link || !address || !status || !closeButton || !copyButton) return null;

    function setStatus(message) {
        status.textContent = message;
    }

    function closeModal() {
        modal.classList.add('display-none');
    }

    function copyAddress() {
        const value = address.value;
        const fallbackCopy = () => {
            address.focus();
            address.select();
            let copied = false;
            try {
                copied = document.execCommand('copy');
            } catch (e) {
                copied = false;
            }
            setStatus(copied
                ? 'Address copied. Paste it into the address bar of a new tab.'
                : 'Could not copy automatically. The address is selected: press Ctrl + C.');
        };
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(value)
                .then(() => setStatus('Address copied. Paste it into the address bar of a new tab.'))
                .catch(fallbackCopy);
        } else {
            fallbackCopy();
        }
    }

    // A plain left click is a page-started navigation and gets blocked, so point the user
    // to the context menu instead. Middle/Ctrl-click are left alone in case they work.
    link.addEventListener('click', (event) => {
        if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey) return;
        event.preventDefault();
        setStatus('Right-click the link and choose "Open link in new tab".');
    });

    address.addEventListener('focus', () => address.select());

    closeButton.addEventListener('click', closeModal);
    copyButton.addEventListener('click', copyAddress);

    modal.addEventListener('click', (event) => {
        if (event.target === modal) closeModal();
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && !modal.classList.contains('display-none')) closeModal();
    });

    return function openFallbackModal(item) {
        const title = item.querySelector('.nav-item-title')?.textContent.trim() || 'this tool';
        const src = item.dataset.src;
        const separator = src.indexOf('?') === -1 ? '?' : '&';
        const url = new URL(src + separator + 'theme=' + currentTheme(), window.location.href).href;
        text.textContent = `This computer's browser settings don't allow CryptoToolbox to open tools by itself. ` +
            `To open "${title}", right-click the link below and choose "Open link in new tab", ` +
            `or copy the address and paste it into the address bar of a new tab.`;
        link.href = url;
        link.textContent = title;
        address.value = url;
        setStatus('');
        modal.classList.remove('display-none');
        copyButton.focus();
    };
}

function initToolNav() {
    const openFallbackModal = initFrameFallback();
    document.querySelectorAll('.nav-item[data-type="frame"]').forEach((item) => {
        item.addEventListener('click', () => {
            whenFrameSupportKnown((support) => {
                if (support === 'blocked' && openFallbackModal) openFallbackModal(item);
                else loadTool(item);
            });
        });
    });
}

initFrameProbe();
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

    // Every opened tool stays alive in the background, so all of them get the new theme.
    function broadcastTheme(value) {
        toolFrames.forEach((frame) => postTheme(frame, value));
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
        const title = link.querySelector('.nav-item-title')?.textContent.trim() || link.dataset.linkTitle || 'the website';
        text.textContent = `Do you want to leave CryptoToolbox and open "${title}" in a new tab?`;
        modal.classList.remove('display-none');
    }

    function closeModal() {
        modal.classList.add('display-none');
        pendingHref = null;
    }

    // Sidebar link entries and other external links marked with data-external-link (e.g. the footer)
    document.querySelectorAll('.nav-item--link, a[data-external-link]').forEach((link) => {
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