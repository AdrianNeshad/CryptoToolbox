/* =========================================================================
   SECO decrypt core — ported byte-by-byte from the node packages that
   the original script (secoUnlock) uses:
     seco-file / secure-container  → file format + AES-256-GCM
     scryptsy                      → scrypt (key stretching)
     bitcoin-seed + bip39          → entropy → mnemonic
   Runs fully locally via WebCrypto (crypto.subtle) + DecompressionStream.
   ========================================================================= */

/* ---------- scrypt (port of scryptsy) ---------- */

function readUInt32LE(a, o) {
    return ((a[o]) | (a[o + 1] << 8) | (a[o + 2] << 16) | (a[o + 3] << 24));
}

function blockxor(S, Si, D, Di, len) {
    for (let i = 0; i < len; i++) D[Di + i] ^= S[Si + i];
}

function R(a, b) { return (a << b) | (a >>> (32 - b)); }

function salsa20_8(B, B32, x) {
    let i;
    for (i = 0; i < 16; i++) {
        B32[i] = (B[i * 4 + 0] & 0xff) << 0;
        B32[i] |= (B[i * 4 + 1] & 0xff) << 8;
        B32[i] |= (B[i * 4 + 2] & 0xff) << 16;
        B32[i] |= (B[i * 4 + 3] & 0xff) << 24;
    }
    for (i = 0; i < 16; i++) x[i] = B32[i];
    for (i = 8; i > 0; i -= 2) {
        x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
        x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
        x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
        x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
        x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
        x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
        x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
        x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
    }
    for (i = 0; i < 16; ++i) B32[i] = x[i] + B32[i];
    for (i = 0; i < 16; i++) {
        const bi = i * 4;
        B[bi + 0] = (B32[i] >> 0 & 0xff);
        B[bi + 1] = (B32[i] >> 8 & 0xff);
        B[bi + 2] = (B32[i] >> 16 & 0xff);
        B[bi + 3] = (B32[i] >> 24 & 0xff);
    }
}

function blockmix_salsa8(BY, Bi, Yi, r, _X, B32, x) {
    let i;
    _X.set(BY.subarray(Bi + (2 * r - 1) * 64, Bi + (2 * r - 1) * 64 + 64), 0);
    for (i = 0; i < 2 * r; i++) {
        blockxor(BY, i * 64, _X, 0, 64);
        salsa20_8(_X, B32, x);
        BY.set(_X.subarray(0, 64), Yi + (i * 64));
    }
    for (i = 0; i < r; i++) {
        BY.set(BY.subarray(Yi + (i * 2) * 64, Yi + (i * 2) * 64 + 64), Bi + (i * 64));
    }
    for (i = 0; i < r; i++) {
        BY.set(BY.subarray(Yi + (i * 2 + 1) * 64, Yi + (i * 2 + 1) * 64 + 64), Bi + (i + r) * 64);
    }
}

function smixSync(B, Bi, r, N, V, XY, _X, B32, x) {
    const Xi = 0;
    const Yi = 128 * r;
    XY.set(B.subarray(Bi, Bi + Yi), Xi);
    for (let i = 0; i < N; i++) {
        V.set(XY.subarray(Xi, Xi + Yi), i * Yi);
        blockmix_salsa8(XY, Xi, Yi, r, _X, B32, x);
    }
    for (let i = 0; i < N; i++) {
        const offset = Xi + (2 * r - 1) * 64;
        const j = readUInt32LE(XY, offset) & (N - 1);
        blockxor(V, j * Yi, XY, Xi, Yi);
        blockmix_salsa8(XY, Xi, Yi, r, _X, B32, x);
    }
    B.set(XY.subarray(Xi, Xi + Yi), Bi);
}

async function pbkdf2Sha256(passwordBytes, saltBytes, iterations, dkLenBytes) {
    const key = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations }, key, dkLenBytes * 8);
    return new Uint8Array(bits);
}

async function scrypt(passwordBytes, saltBytes, N, r, p, dkLen) {
    if ((N & (N - 1)) !== 0 || N === 0) throw new Error('N must be a power of 2');
    const XY = new Uint8Array(256 * r);
    const V = new Uint8Array(128 * r * N);
    const B32 = new Int32Array(16);
    const x = new Int32Array(16);
    const _X = new Uint8Array(64);
    const B = await pbkdf2Sha256(passwordBytes, saltBytes, 1, p * 128 * r);
    for (let i = 0; i < p; i++) smixSync(B, i * 128 * r, r, N, V, XY, _X, B32, x);
    return pbkdf2Sha256(passwordBytes, B, 1, dkLen);
}

/* ---------- AES-256-GCM ---------- */

async function aesGcmDecrypt(keyBytes, ciphertext, iv, authTag) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const data = new Uint8Array(ciphertext.length + authTag.length);
    data.set(ciphertext, 0);
    data.set(authTag, ciphertext.length);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, data);
    return new Uint8Array(pt);
}

/* ---------- gunzip ---------- */

async function gunzip(bytes) {
    const ds = new DecompressionStream('gzip');
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    const buf = await new Response(stream).arrayBuffer();
    return new Uint8Array(buf);
}

/* ---------- SECO file parsing ---------- */

function parseSeco(fileBytes) {
    // header(224) checksum(32) metadata(256) blobLen(UInt32BE) blob(blobLen)
    if (fileBytes.length < 224 + 32 + 256 + 4) {
        throw new Error('The file is too small to be a valid .seco file.');
    }
    const magic = String.fromCharCode(fileBytes[0], fileBytes[1], fileBytes[2], fileBytes[3]);
    if (magic !== 'SECO') {
        throw new Error('Invalid file: missing the "SECO" signature. Is this really a seed.seco file?');
    }
    const metadataOffset = 224 + 32;
    const md = fileBytes.subarray(metadataOffset, metadataOffset + 256);
    const dv = new DataView(md.buffer, md.byteOffset, md.byteLength);
    const meta = {
        salt: md.subarray(0, 32),
        n: dv.getUint32(32, false),
        r: dv.getUint32(36, false),
        p: dv.getUint32(40, false),
        blobKey: {
            iv: md.subarray(76, 88),
            authTag: md.subarray(88, 104),
            key: md.subarray(104, 136),
        },
        blob: {
            iv: md.subarray(136, 148),
            authTag: md.subarray(148, 164),
        },
    };
    const blobLenOffset = metadataOffset + 256;
    const fdv = new DataView(fileBytes.buffer, fileBytes.byteOffset, fileBytes.byteLength);
    const blobLen = fdv.getUint32(blobLenOffset, false);
    const blob = fileBytes.subarray(blobLenOffset + 4, blobLenOffset + 4 + blobLen);
    return { meta, blob };
}

/* ---------- entropy → mnemonic (BIP39) ---------- */

function bytesToBinary(bytes) {
    return Array.from(bytes).map(b => b.toString(2).padStart(8, '0')).join('');
}

async function sha256Bytes(bytes) {
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(hash);
}

async function entropyToMnemonic(entropyBytes, wordlist) {
    const hash = await sha256Bytes(entropyBytes);
    const entropyBits = bytesToBinary(entropyBytes);
    const checksumBits = bytesToBinary(hash).slice(0, entropyBytes.length / 4);
    const bits = entropyBits + checksumBits;
    const words = [];
    for (let i = 0; i < bits.length / 11; i++) {
        words.push(wordlist[parseInt(bits.slice(i * 11, (i + 1) * 11), 2)]);
    }
    return words.join(' ');
}

/* ---------- decrypt with ONE password ---------- */

// Returns the raw secret bytes on the correct password; throws OperationError on
// a wrong password (GCM auth fail). Wordlist-free so it can run inside a Worker.
async function tryPasswordCore(parsed, password) {
    const { meta, blob } = parsed;
    const pwBytes = new TextEncoder().encode(password);
    const derivedKey = await scrypt(pwBytes, meta.salt, meta.n, meta.r, meta.p, 32);
    // GCM auth fails → wrong password → throws OperationError
    const blobKey = await aesGcmDecrypt(derivedKey, meta.blobKey.key, meta.blobKey.iv, meta.blobKey.authTag);
    const data = await aesGcmDecrypt(blobKey, blob, meta.blob.iv, meta.blob.authTag);
    // shrink: UInt32BE(0) = t, slice(4, t+4)
    const t = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0, false);
    const shrinked = data.subarray(4, 4 + t);
    const gunzipped = await gunzip(shrinked);
    return gunzipped.subarray(64);
}

// Converts the recovered secret bytes into a BIP39 phrase (or raw text). Runs on
// the main thread only, since it needs the 2048-word list.
async function secretToPhrase(rest, wordlist) {
    if (rest.length === 16 || rest.length === 32) return entropyToMnemonic(rest, wordlist);
    return new TextDecoder().decode(rest);
}

/* =========================================================================
   Parallel sweep across Web Workers — built inline from the crypto functions
   above (via Function.prototype.toString), so they need no separate file and
   work both in the Electron app and when opened directly from file://. Each
   worker owns a contiguous slice of the password list. A single-threaded
   fallback runs if Workers/subtle are unavailable.
   ========================================================================= */

const WORKER_FNS = [
    readUInt32LE, blockxor, R, salsa20_8, blockmix_salsa8, smixSync,
    pbkdf2Sha256, scrypt, aesGcmDecrypt, gunzip, tryPasswordCore,
];

const WORKER_BOOTSTRAP = `
let __stop = false;
self.onmessage = async function (e) {
    const m = e.data || {};
    if (m.type === 'stop') { __stop = true; return; }
    if (m.type === 'ping') {
        try { await crypto.subtle.digest('SHA-256', new Uint8Array([0])); self.postMessage({ type: 'pong' }); }
        catch (err) { self.postMessage({ type: 'error', message: 'crypto.subtle unavailable in worker' }); }
        return;
    }
    if (m.type !== 'start') return;
    __stop = false;
    try {
        const parsed = m.parsed, passwords = m.passwords, base = m.base;
        let since = 0;
        for (let i = 0; i < passwords.length; i++) {
            if (__stop) break;
            let rest = null;
            try { rest = await tryPasswordCore(parsed, passwords[i]); } catch (_) { rest = null; }
            since++;
            if (rest) {
                self.postMessage({ type: 'progress', delta: since });
                self.postMessage({ type: 'found', index: base + i, password: passwords[i], rest: rest });
                return;
            }
            if (since >= 8) {
                self.postMessage({ type: 'progress', delta: since });
                since = 0;
                await new Promise(function (r) { setTimeout(r, 0); }); // let 'stop' arrive
                if (__stop) break;
            }
        }
        if (since) self.postMessage({ type: 'progress', delta: since });
        self.postMessage({ type: 'done' });
    } catch (err) {
        self.postMessage({ type: 'error', message: String(err && err.message ? err.message : err) });
    }
};
`;

let _workerUrl = null;
function getWorkerUrl() {
    if (_workerUrl) return _workerUrl;
    const src = WORKER_FNS.map(fn => fn.toString()).join('\n\n') + '\n\n' + WORKER_BOOTSTRAP;
    _workerUrl = URL.createObjectURL(new Blob([src], { type: 'application/javascript' }));
    return _workerUrl;
}

let _workersUsable = null;
async function workersUsable() {
    if (_workersUsable !== null) return _workersUsable;
    if (typeof Worker === 'undefined') { _workersUsable = false; return false; }
    let w = null;
    try { w = new Worker(getWorkerUrl()); } catch (e) { _workersUsable = false; return false; }
    const ok = await new Promise((resolve) => {
        const to = setTimeout(() => resolve(false), 3000);
        w.onmessage = (e) => {
            if (e.data && e.data.type === 'pong') { clearTimeout(to); resolve(true); }
            else if (e.data && e.data.type === 'error') { clearTimeout(to); resolve(false); }
        };
        w.onerror = () => { clearTimeout(to); resolve(false); };
        try { w.postMessage({ type: 'ping' }); } catch (e) { clearTimeout(to); resolve(false); }
    });
    try { w.terminate(); } catch (e) { /* ignore */ }
    _workersUsable = ok;
    return ok;
}

let activeWorkers = [];

// Split the password list across workers; resolve with the first match.
function runWithWorkers(parsed, passwords, onProgress) {
    return new Promise((resolve) => {
        const total = passwords.length;
        let nThreads = navigator.hardwareConcurrency || 4;
        nThreads = Math.max(1, Math.min(nThreads, 16, total));
        const chunk = Math.ceil(total / nThreads);
        const workers = [];
        let finished = 0;
        let settled = false;

        const cleanup = () => {
            workers.forEach(w => { try { w.terminate(); } catch (e) { /* ignore */ } });
            activeWorkers = [];
        };

        for (let t = 0; t < nThreads; t++) {
            const base = t * chunk;
            const slice = passwords.slice(base, base + chunk);
            if (slice.length === 0) continue;
            const w = new Worker(getWorkerUrl());
            workers.push(w);
            w.onmessage = (e) => {
                const msg = e.data || {};
                if (settled) return;
                if (msg.type === 'progress') {
                    onProgress(msg.delta);
                } else if (msg.type === 'found') {
                    settled = true; cleanup();
                    resolve({ found: true, index: msg.index, password: msg.password, rest: new Uint8Array(msg.rest) });
                } else if (msg.type === 'done') {
                    finished++;
                    if (finished >= workers.length) { settled = true; cleanup(); resolve({ found: false, stopped: stopRequested }); }
                } else if (msg.type === 'error') {
                    settled = true; cleanup(); resolve({ found: false, error: msg.message });
                }
            };
            w.onerror = (err) => {
                if (settled) return;
                settled = true; cleanup();
                resolve({ found: false, error: (err && err.message) || 'worker error' });
            };
            w.postMessage({ type: 'start', parsed, passwords: slice, base });
        }

        activeWorkers = workers;
        if (workers.length === 0) resolve({ found: false });
    });
}

// Single-threaded fallback (Workers unavailable) — same cooperative yield model
// the tool used before.
async function runSingleThread(parsed, passwords, onProgress) {
    let since = 0;
    for (let i = 0; i < passwords.length; i++) {
        if (stopRequested) return { found: false, stopped: true };
        let rest = null;
        try { rest = await tryPasswordCore(parsed, passwords[i]); } catch (_) { rest = null; }
        since++;
        if (rest) { onProgress(since); return { found: true, index: i, password: passwords[i], rest }; }
        if (since >= 4) { onProgress(since); since = 0; await yieldToUI(); }
    }
    if (since) onProgress(since);
    return { found: false };
}

/* =========================================================================
   UI
   ========================================================================= */

const $ = id => document.getElementById(id);

const secoBtn = $('seco-btn');
const secoInput = $('seco-input');
const secoName = $('seco-name');
const pwBtn = $('pw-btn');
const pwInput = $('pw-input');
const pwName = $('pw-name');
const pwCount = $('pw-count');
const pwList = $('pw-list');
const runBtn = $('run-btn');
const stopBtn = $('stop-btn');
const progressWrap = $('progress-wrap');
const progressBar = $('progress-bar');
const progressStatus = $('progress-status');
const resultPanel = $('result-panel');
const resultTitle = $('result-title');
const resultBody = $('result-body');
const output = $('output');
const clearBtn = $('clear-btn');
const toast = $('toast');

let secoBytes = null;   // Uint8Array
let running = false;
let stopRequested = false;

/* MessageChannel-based yield: allows a repaint between passwords
   without the setTimeout(0) ~4 ms clamp. */
const _mc = new MessageChannel();
let _yieldResolve = null;
_mc.port1.onmessage = () => { if (_yieldResolve) { const r = _yieldResolve; _yieldResolve = null; r(); } };
function yieldToUI() {
    return new Promise(resolve => { _yieldResolve = resolve; _mc.port2.postMessage(0); });
}

/* ---------- output log ---------- */

function log(text, cls) {
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = text + '\n';
    output.appendChild(span);
    output.scrollTop = output.scrollHeight;
}

function clearOutput() {
    output.textContent = '';
}

function showToast(text) {
    toast.textContent = text;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2200);
}

/* ---------- password counter ---------- */

function parsePasswords() {
    return pwList.value.split('\n').map(p => p.trim()).filter(p => p.length > 0);
}

function updatePwCount() {
    const n = parsePasswords().length;
    pwCount.textContent = n > 0 ? `${n} passwords` : '';
}

pwList.addEventListener('input', updatePwCount);

/* ---------- file selection ---------- */

function setSecoName(text, state, title) {
    secoName.textContent = text;
    secoName.classList.remove('set', 'valid', 'invalid');
    if (state) secoName.classList.add(state);
    if (title) secoName.title = title; else secoName.removeAttribute('title');
}

secoBtn.addEventListener('click', () => secoInput.click());

secoInput.addEventListener('change', async () => {
    const file = secoInput.files[0];
    if (!file) return;
    try {
        const buf = await file.arrayBuffer();
        secoBytes = new Uint8Array(buf);
        const label = `${file.name} (${secoBytes.length} byte)`;
        // Validate signature/size → green text if valid, red if not
        try {
            parseSeco(secoBytes);
            setSecoName(label, 'valid', 'Valid .seco file');
        } catch (e) {
            setSecoName(label, 'invalid', 'Invalid .seco file: ' + e.message);
        }
    } catch (e) {
        secoBytes = null;
        setSecoName('Could not read the file', null);
    }
});

pwBtn.addEventListener('click', () => pwInput.click());

pwInput.addEventListener('change', async () => {
    const file = pwInput.files[0];
    if (!file) return;
    try {
        const text = await file.text();
        pwList.value = text;
        pwName.textContent = file.name;
        pwName.classList.add('set');
        updatePwCount();
    } catch (e) {
        pwName.textContent = 'Could not read the file';
        pwName.classList.remove('set');
    }
});

/* ---------- run ---------- */

function setRunning(state) {
    running = state;
    runBtn.classList.toggle('display-none', state);
    stopBtn.classList.toggle('display-none', !state);
    secoBtn.disabled = state;
    pwBtn.disabled = state;
    pwList.disabled = state;
}

function showResult(success, titleText, fields) {
    resultPanel.classList.remove('display-none', 'success', 'fail');
    resultPanel.classList.add(success ? 'success' : 'fail');
    resultTitle.textContent = titleText;
    resultBody.innerHTML = '';
    (fields || []).forEach(f => {
        const field = document.createElement('div');
        field.className = 'result-field';
        const label = document.createElement('div');
        label.className = 'result-label';
        label.textContent = f.label;
        const valueRow = document.createElement('div');
        valueRow.className = 'result-value';
        const code = document.createElement('code');
        code.textContent = f.value;
        valueRow.appendChild(code);
        const btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.textContent = 'Copy';
        btn.addEventListener('click', () => {
            navigator.clipboard.writeText(f.value);
            showToast(f.label + ' copied');
        });
        valueRow.appendChild(btn);
        field.appendChild(label);
        field.appendChild(valueRow);
        resultBody.appendChild(field);
    });
}

runBtn.addEventListener('click', run);
stopBtn.addEventListener('click', () => {
    stopRequested = true;
    progressStatus.textContent = 'Stopping…';
    activeWorkers.forEach(w => { try { w.postMessage({ type: 'stop' }); } catch (e) { /* ignore */ } });
});

function fmtDuration(sec) {
    if (!isFinite(sec) || sec < 0) return '?';
    sec = Math.round(sec);
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    return (h ? h + 'h ' : '') + (h || m ? m + 'm ' : '') + s + 's';
}

async function run() {
    if (running) return;

    if (!secoBytes) { showToast('Choose a .seco file first'); return; }
    const passwords = parsePasswords();
    if (passwords.length === 0) { showToast('Add at least one password'); return; }

    if (typeof DecompressionStream === 'undefined') {
        clearOutput();
        log('Your browser lacks DecompressionStream (gzip) support — cannot continue.', 'log-err');
        return;
    }

    const wordlist = window.entropyWordlists.bip39;

    // Parse the .seco file
    let parsed;
    try {
        parsed = parseSeco(secoBytes);
    } catch (e) {
        clearOutput();
        resultPanel.classList.add('display-none');
        log('Error: ' + e.message, 'log-err');
        return;
    }

    stopRequested = false;
    setRunning(true);
    resultPanel.classList.add('display-none');
    progressWrap.classList.remove('display-none');
    progressBar.style.width = '0%';
    clearOutput();

    const total = passwords.length;
    const useWorkers = await workersUsable();
    const nThreads = useWorkers ? Math.max(1, Math.min(navigator.hardwareConcurrency || 4, 16, total)) : 1;

    log(`scrypt parameters: N=${parsed.meta.n}, r=${parsed.meta.r}, p=${parsed.meta.p}`, 'log-muted');
    log(`Testing ${total} passwords…`, 'log-muted');
    log(useWorkers ? `workers: ${nThreads} threads` : 'workers: unavailable — running single-threaded', 'log-muted');

    let done = 0;
    const t0 = performance.now();
    const onProgress = (delta) => { done += delta; };

    const timer = setInterval(() => {
        const elapsed = (performance.now() - t0) / 1000;
        const rate = done / Math.max(elapsed, 0.001);
        const eta = rate > 0 ? (total - done) / rate : Infinity;
        const pct = Math.min(100, (done / total) * 100).toFixed(1);
        progressBar.style.width = pct + '%';
        progressStatus.textContent = `${done}/${total} (${pct}%)  ${Math.round(rate)}/s  elapsed ${fmtDuration(elapsed)}  ETA ${fmtDuration(eta)}`;
    }, 300);

    let result;
    try {
        result = useWorkers
            ? await runWithWorkers(parsed, passwords, onProgress)
            : await runSingleThread(parsed, passwords, onProgress);
    } catch (e) {
        result = { found: false, error: (e && e.message) || String(e) };
    }

    clearInterval(timer);
    const secs = ((performance.now() - t0) / 1000).toFixed(1);

    if (result.error) {
        progressBar.style.width = '0%';
        progressStatus.textContent = 'Error';
        log('\nError during run: ' + result.error, 'log-err');
        setRunning(false);
        return;
    }

    if (result.found) {
        progressBar.style.width = '100%';
        let phrase;
        try { phrase = await secretToPhrase(result.rest, wordlist); }
        catch (e) { phrase = '(could not decode secret: ' + e.message + ')'; }
        progressStatus.textContent = `Done — password found on attempt ${result.index + 1} of ${total} (${secs}s)`;
        log(`\n✓ MATCH on password #${result.index + 1}: ${result.password}`, 'log-hit');
        log(`Mnemonic: ${phrase}`, 'log-ok');
        showResult(true, '✓ Password found!', [
            { label: 'Password', value: result.password },
            { label: 'Seed phrase (mnemonic)', value: phrase },
        ]);
    } else if (result.stopped || stopRequested) {
        progressStatus.textContent = `Stopped (${secs}s)`;
        log('\nStopped by the user.', 'log-err');
    } else {
        progressBar.style.width = '100%';
        progressStatus.textContent = `Done — no matching password (${secs}s)`;
        log(`\n✗ None of the ${total} passwords matched.`, 'log-err');
        showResult(false, '✗ No matching password', [
            { label: 'Result', value: `Tested ${total} passwords with no match. Check the list or add more.` },
        ]);
    }

    setRunning(false);
}

clearBtn.addEventListener('click', () => {
    clearOutput();
    output.textContent = 'Waiting to run…';
    progressWrap.classList.add('display-none');
    resultPanel.classList.add('display-none');
});

/* ---------- theme sync with CryptoToolbox ---------- */
window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    var data = event.data;
    if (data && data.source === 'cryptotoolbox' && data.type === 'theme' &&
        (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignored */ }
    }
});
