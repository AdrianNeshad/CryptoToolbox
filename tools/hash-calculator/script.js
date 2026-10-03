const hashing = window.ToolboxHashing;

const textInput = document.getElementById('text-input');
const fileInput = document.getElementById('file-input');
const fileDrop = document.getElementById('file-drop');
const fileLabel = document.getElementById('file-label');
const expectedInput = document.getElementById('expected-input');
const statusEl = document.getElementById('status');
const results = document.getElementById('results');
const verdict = document.getElementById('verdict');
const progress = document.getElementById('progress');
const progressBar = document.getElementById('progress-bar');
const hashButton = document.getElementById('hash-button');
const cancelButton = document.getElementById('cancel-button');
const toast = document.getElementById('toast');

const ALGO_STORAGE_KEY = 'hash-calculator-algos';
const DEFAULT_ALGOS = ['md5', 'sha1', 'sha256'];

const ALGORITHMS = [
    { id: 'md5', label: 'MD5' },
    { id: 'sha1', label: 'SHA-1' },
    { id: 'sha256', label: 'SHA-256' },
    { id: 'sha384', label: 'SHA-384' },
    { id: 'sha512', label: 'SHA-512' },
    { id: 'crc32', label: 'CRC-32' },
];

const FILE_PLACEHOLDER = 'Choose a file or drag it here';

let mode = 'text';
let selectedFile = null;
// The source is kept as a Blob so recomputing after an algorithm change does not
// require the whole file in memory — a File is just a reference to disk.
let lastSource = null;
let lastLabel = '';
let lastHashes = null;
let running = false;
let cancelRequested = false;

function setStatus(msg, isError) {
    statusEl.textContent = msg;
    statusEl.style.color = isError ? 'var(--error)' : 'var(--text-muted)';
}

function showToast() {
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 1400);
}

function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    const units = ['kB', 'MB', 'GB', 'TB'];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i++;
    }
    return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

function selectedAlgos() {
    return ALGORITHMS
        .map((algo) => algo.id)
        .filter((id) => {
            const el = document.querySelector(`input[name="algo"][value="${id}"]`);
            return el && el.checked;
        });
}

function persistAlgos() {
    try {
        localStorage.setItem(ALGO_STORAGE_KEY, JSON.stringify(selectedAlgos()));
    } catch (e) {
        /* ignored */
    }
}

function restoreAlgos() {
    let saved = null;
    try {
        saved = JSON.parse(localStorage.getItem(ALGO_STORAGE_KEY) || 'null');
    } catch (e) {
        saved = null;
    }
    const chosen = Array.isArray(saved) && saved.length ? saved : DEFAULT_ALGOS;
    document.querySelectorAll('input[name="algo"]').forEach((input) => {
        input.checked = chosen.includes(input.value);
    });
}

function renderHashes(hashes, ids) {
    results.innerHTML = '';
    ids.forEach((id) => {
        const algo = ALGORITHMS.find((a) => a.id === id);
        const row = document.createElement('div');
        row.className = 'result-row';
        row.dataset.algo = id;

        const name = document.createElement('span');
        name.className = 'algo';
        name.textContent = algo.label;

        const value = document.createElement('code');
        value.textContent = hashes[id] || '';

        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'copy-btn';
        copy.textContent = 'Copy';
        copy.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(value.textContent);
                showToast();
            } catch (e) {
                setStatus('Could not copy', true);
            }
        });

        row.append(name, value, copy);
        results.appendChild(row);
    });
    results.classList.remove('display-none');
}

// Compares a pasted known hash against what was computed. The algorithm is
// inferred from the hex length, so the user doesn't have to say which it is.
function applyVerdict() {
    results.querySelectorAll('.result-row').forEach((row) => {
        row.classList.remove('is-match', 'is-mismatch');
    });

    const expected = hashing.normalizeExpected(expectedInput.value);
    if (!expected || !lastHashes) {
        verdict.classList.add('display-none');
        verdict.textContent = '';
        return;
    }

    function show(text, kind) {
        verdict.textContent = text;
        verdict.classList.remove('display-none', 'is-match', 'is-mismatch');
        if (kind) verdict.classList.add(kind);
    }

    const candidates = hashing.matchAlgosByLength(expected);
    if (!candidates.length) {
        show(`The hex length (${expected.length} characters) doesn't match any of the algorithms.`, null);
        return;
    }

    const computed = candidates.filter((id) => lastHashes[id]);
    if (!computed.length) {
        const labels = candidates
            .map((id) => ALGORITHMS.find((a) => a.id === id).label)
            .join('/');
        show(`Looks like ${labels} — tick that algorithm to compare.`, null);
        return;
    }

    const match = computed.find((id) => lastHashes[id] === expected);
    const target = match || computed[0];
    const label = ALGORITHMS.find((a) => a.id === target).label;
    const row = results.querySelector(`.result-row[data-algo="${target}"]`);

    if (match) {
        show(`Match — ${label} is identical to the known hash.`, 'is-match');
        if (row) row.classList.add('is-match');
    } else {
        show(`No match — ${label} differs from the known hash.`, 'is-mismatch');
        if (row) row.classList.add('is-mismatch');
    }
}

function setRunning(value, streaming) {
    running = value;
    hashButton.disabled = value;
    hashButton.textContent = value ? 'Computing…' : 'Compute';
    cancelButton.classList.toggle('display-none', !(value && streaming));
    progress.classList.toggle('display-none', !(value && streaming));
    if (!value) progressBar.style.width = '0';
}

async function compute(source, statusText) {
    const ids = selectedAlgos();
    if (!ids.length) {
        setStatus('Select at least one algorithm', true);
        results.classList.add('display-none');
        verdict.classList.add('display-none');
        return;
    }

    const streaming = source.size > hashing.ONESHOT_LIMIT;
    cancelRequested = false;
    setRunning(true, streaming);
    setStatus(streaming ? `${statusText} — reading in chunks…` : statusText);

    try {
        const hashes = await hashing.hashBlob(
            source,
            ids,
            (done, total) => {
                if (!streaming || !total) return;
                progressBar.style.width = `${(done / total) * 100}%`;
                setStatus(`${statusText} — ${Math.floor((done / total) * 100)} %`);
            },
            () => cancelRequested,
        );

        if (hashes === null) {
            setStatus('Cancelled', true);
            return;
        }

        lastSource = source;
        lastLabel = statusText;
        lastHashes = hashes;
        setStatus(statusText);
        renderHashes(hashes, ids);
        applyVerdict();
    } catch (err) {
        setStatus('Could not compute hash', true);
        console.error(err);
    } finally {
        setRunning(false, streaming);
    }
}

function acceptFile(file) {
    if (!file) return;
    selectedFile = file;
    fileLabel.textContent = `${file.name} (${formatBytes(file.size)})`;
}

function switchMode(next) {
    mode = next;
    document.querySelectorAll('.tab').forEach((t) => {
        t.classList.toggle('active', t.dataset.mode === next);
    });
    document.getElementById('text-panel').classList.toggle('display-none', next !== 'text');
    document.getElementById('file-panel').classList.toggle('display-none', next !== 'file');
}

document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => switchMode(tab.dataset.mode));
});

fileInput.addEventListener('change', () => {
    acceptFile(fileInput.files[0] || null);
});

// Dropped files were previously not accepted even though the box invited it.
['dragenter', 'dragover'].forEach((type) => {
    fileDrop.addEventListener(type, (event) => {
        event.preventDefault();
        fileDrop.classList.add('is-dragover');
    });
});

['dragleave', 'dragend'].forEach((type) => {
    fileDrop.addEventListener(type, () => fileDrop.classList.remove('is-dragover'));
});

fileDrop.addEventListener('drop', (event) => {
    event.preventDefault();
    fileDrop.classList.remove('is-dragover');
    const file = event.dataTransfer && event.dataTransfer.files[0];
    if (file) {
        switchMode('file');
        acceptFile(file);
    }
});

// Without this, Chromium opens the file instead of the app receiving it.
['dragover', 'drop'].forEach((type) => {
    document.addEventListener(type, (event) => {
        if (!fileDrop.contains(event.target)) event.preventDefault();
    });
});

hashButton.addEventListener('click', async () => {
    if (running) return;
    if (mode === 'text') {
        const text = textInput.value;
        if (!text) {
            setStatus('Paste some text first', true);
            return;
        }
        const bytes = new TextEncoder().encode(text);
        await compute(new Blob([bytes]), `${text.length} characters`);
    } else {
        if (!selectedFile) {
            setStatus('Choose a file first', true);
            return;
        }
        await compute(selectedFile, `${selectedFile.name} (${formatBytes(selectedFile.size)})`);
    }
});

cancelButton.addEventListener('click', () => {
    cancelRequested = true;
});

document.getElementById('clear-button').addEventListener('click', () => {
    cancelRequested = true;
    textInput.value = '';
    fileInput.value = '';
    expectedInput.value = '';
    selectedFile = null;
    lastSource = null;
    lastLabel = '';
    lastHashes = null;
    fileLabel.textContent = FILE_PLACEHOLDER;
    results.classList.add('display-none');
    results.innerHTML = '';
    verdict.classList.add('display-none');
    verdict.textContent = '';
    setStatus('No data loaded');
});

expectedInput.addEventListener('input', applyVerdict);

document.querySelectorAll('input[name="algo"]').forEach((input) => {
    input.addEventListener('change', async () => {
        persistAlgos();
        if (!lastSource || running) return;
        // The status line may hold progress text, so the description is stored separately.
        await compute(lastSource, lastLabel);
    });
});

restoreAlgos();

window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    const data = event.data;
    if (data && data.source === 'cryptotoolbox' && data.type === 'theme' &&
        (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignored */ }
    }
});
