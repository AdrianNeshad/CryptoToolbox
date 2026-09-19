/* =========================================================================
   DeFiChain Light Wallet unlock core — a local re-implementation of
   @defichain/jellyfish-wallet-encrypted's PrivateKeyEncryption /
   EncryptedData format, ported from the reference Node script.

   Two blob shapes share the exact same format, differing only in the
   scrypt cost parameters and in what the plaintext is:

     mnemonic scheme  N=16384,r=8,p=1  plaintext = BIP39 entropy   (raw hex)
     wallet scheme    N=512,  r=8,p=2  plaintext = BIP32 root key  (JSON)

   The wallet is protected by a 6-digit numeric passcode, so this tool sweeps
   the whole 000000–999999 range. A correct code is detected via the 4-byte
   double-SHA256 checksum embedded in every blob (false positives ~1 in 4.3e9).

   Everything runs locally: scrypt is a pure-JS port; SHA-256 and AES-256-CTR
   use WebCrypto (crypto.subtle). No network access. The heavy sweep is split
   across Web Workers (built inline from this same source, so they work both
   inside the Electron app and when the page is opened directly via file://).
   ========================================================================= */

/* =========================================================================
   Crypto — these functions are self-contained (they reference only each
   other and platform globals: self.crypto, TextEncoder). They are stringified
   via Function.prototype.toString() to build the Web Worker, and are ALSO
   called directly on the main thread for the no-worker fallback.
   ========================================================================= */

function dfcReadUInt32LE(a, o) {
    return ((a[o]) | (a[o + 1] << 8) | (a[o + 2] << 16) | (a[o + 3] << 24));
}

function dfcBlockxor(S, Si, D, Di, len) {
    for (let i = 0; i < len; i++) D[Di + i] ^= S[Si + i];
}

function dfcRotl(a, b) { return (a << b) | (a >>> (32 - b)); }

function dfcSalsa20_8(B, B32, x) {
    let i;
    for (i = 0; i < 16; i++) {
        B32[i] = (B[i * 4 + 0] & 0xff) << 0;
        B32[i] |= (B[i * 4 + 1] & 0xff) << 8;
        B32[i] |= (B[i * 4 + 2] & 0xff) << 16;
        B32[i] |= (B[i * 4 + 3] & 0xff) << 24;
    }
    for (i = 0; i < 16; i++) x[i] = B32[i];
    for (i = 8; i > 0; i -= 2) {
        x[4] ^= dfcRotl(x[0] + x[12], 7); x[8] ^= dfcRotl(x[4] + x[0], 9);
        x[12] ^= dfcRotl(x[8] + x[4], 13); x[0] ^= dfcRotl(x[12] + x[8], 18);
        x[9] ^= dfcRotl(x[5] + x[1], 7); x[13] ^= dfcRotl(x[9] + x[5], 9);
        x[1] ^= dfcRotl(x[13] + x[9], 13); x[5] ^= dfcRotl(x[1] + x[13], 18);
        x[14] ^= dfcRotl(x[10] + x[6], 7); x[2] ^= dfcRotl(x[14] + x[10], 9);
        x[6] ^= dfcRotl(x[2] + x[14], 13); x[10] ^= dfcRotl(x[6] + x[2], 18);
        x[3] ^= dfcRotl(x[15] + x[11], 7); x[7] ^= dfcRotl(x[3] + x[15], 9);
        x[11] ^= dfcRotl(x[7] + x[3], 13); x[15] ^= dfcRotl(x[11] + x[7], 18);
        x[1] ^= dfcRotl(x[0] + x[3], 7); x[2] ^= dfcRotl(x[1] + x[0], 9);
        x[3] ^= dfcRotl(x[2] + x[1], 13); x[0] ^= dfcRotl(x[3] + x[2], 18);
        x[6] ^= dfcRotl(x[5] + x[4], 7); x[7] ^= dfcRotl(x[6] + x[5], 9);
        x[4] ^= dfcRotl(x[7] + x[6], 13); x[5] ^= dfcRotl(x[4] + x[7], 18);
        x[11] ^= dfcRotl(x[10] + x[9], 7); x[8] ^= dfcRotl(x[11] + x[10], 9);
        x[9] ^= dfcRotl(x[8] + x[11], 13); x[10] ^= dfcRotl(x[9] + x[8], 18);
        x[12] ^= dfcRotl(x[15] + x[14], 7); x[13] ^= dfcRotl(x[12] + x[15], 9);
        x[14] ^= dfcRotl(x[13] + x[12], 13); x[15] ^= dfcRotl(x[14] + x[13], 18);
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

function dfcBlockmix(BY, Bi, Yi, r, _X, B32, x) {
    let i;
    _X.set(BY.subarray(Bi + (2 * r - 1) * 64, Bi + (2 * r - 1) * 64 + 64), 0);
    for (i = 0; i < 2 * r; i++) {
        dfcBlockxor(BY, i * 64, _X, 0, 64);
        dfcSalsa20_8(_X, B32, x);
        BY.set(_X.subarray(0, 64), Yi + (i * 64));
    }
    for (i = 0; i < r; i++) {
        BY.set(BY.subarray(Yi + (i * 2) * 64, Yi + (i * 2) * 64 + 64), Bi + (i * 64));
    }
    for (i = 0; i < r; i++) {
        BY.set(BY.subarray(Yi + (i * 2 + 1) * 64, Yi + (i * 2 + 1) * 64 + 64), Bi + (i + r) * 64);
    }
}

function dfcSmix(B, Bi, r, N, V, XY, _X, B32, x) {
    const Xi = 0;
    const Yi = 128 * r;
    XY.set(B.subarray(Bi, Bi + Yi), Xi);
    for (let i = 0; i < N; i++) {
        V.set(XY.subarray(Xi, Xi + Yi), i * Yi);
        dfcBlockmix(XY, Xi, Yi, r, _X, B32, x);
    }
    for (let i = 0; i < N; i++) {
        const offset = Xi + (2 * r - 1) * 64;
        const j = dfcReadUInt32LE(XY, offset) & (N - 1);
        dfcBlockxor(V, j * Yi, XY, Xi, Yi);
        dfcBlockmix(XY, Xi, Yi, r, _X, B32, x);
    }
    B.set(XY.subarray(Xi, Xi + Yi), Bi);
}

async function dfcPbkdf2(passwordBytes, saltBytes, iterations, dkLenBytes) {
    const key = await self.crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await self.crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations }, key, dkLenBytes * 8);
    return new Uint8Array(bits);
}

// Allocates the reusable scratch buffers scrypt needs for a given (N, r). The
// 16 MB V array dominates, so a sweep allocates this ONCE and reuses it for
// every attempt instead of churning the GC a million times.
function dfcMakeScratch(N, r) {
    return {
        XY: new Uint8Array(256 * r),
        V: new Uint8Array(128 * r * N),
        B32: new Int32Array(16),
        x: new Int32Array(16),
        _X: new Uint8Array(64),
    };
}

// Standard scrypt (RFC 7914) — matches Node's crypto.scryptSync for the same
// (password, salt, N, r, p, dkLen). Pass `scratch` (from dfcMakeScratch) to
// reuse buffers across calls; smix fully overwrites XY/V each call, so reuse is
// safe. Without it, buffers are allocated per call (fine for one-off use).
async function dfcScrypt(passwordBytes, saltBytes, N, r, p, dkLen, scratch) {
    const s = scratch || dfcMakeScratch(N, r);
    const B = await dfcPbkdf2(passwordBytes, saltBytes, 1, p * 128 * r);
    for (let i = 0; i < p; i++) dfcSmix(B, i * 128 * r, r, N, s.V, s.XY, s._X, s.B32, s.x);
    return dfcPbkdf2(passwordBytes, B, 1, dkLen);
}

async function dfcSha256(bytes) {
    return new Uint8Array(await self.crypto.subtle.digest('SHA-256', bytes));
}

// AES256.decrypt from @defichain/jellyfish-crypto: aes-256-ctr, key = SHA256(k2),
// IV = first 16 bytes of the half. WebCrypto AES-CTR with a full 128-bit counter
// matches Node's createDecipheriv('aes-256-ctr', key, iv) byte-for-byte.
async function dfcAesCtrDecrypt(k2, buf) {
    const keyBytes = await dfcSha256(k2);
    const iv = buf.slice(0, 16);
    const ct = buf.slice(16);
    const key = await self.crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt']);
    const pt = await self.crypto.subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 128 }, key, ct);
    return new Uint8Array(pt);
}

// jellyfish's _xor: wraps the key over the data length.
function dfcXor(key, data) {
    const out = new Uint8Array(data.length);
    for (let i = 0, j = 0; i < data.length; i++) {
        out[i] = data[i] ^ (key[j] === undefined ? 0 : key[j]);
        if (j + 1 === data.length) j = 0; else j++;
    }
    return out;
}

function dfcHexToBytes(h) {
    const a = new Uint8Array(h.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
    return a;
}

function dfcBytesToHex(b) {
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
}

function dfcConcat(a, b) {
    const o = new Uint8Array(a.length + b.length);
    o.set(a, 0); o.set(b, a.length);
    return o;
}

function dfcEq(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

// Replicates EncryptedData.decode(): 3 header bytes, 4-byte hash, then two
// equal-length encrypted halves (each = 16-byte IV + ciphertext).
function dfcDecode(encoded) {
    encoded = String(encoded).trim();
    if (encoded.length < 18 || (encoded.length - 14) % 2 !== 0) {
        throw new Error('Invalid encrypted data string');
    }
    if (!/^[0-9a-fA-F]+$/.test(encoded)) {
        throw new Error('Encrypted data must be a hex string');
    }
    const dataLen = encoded.length - 14;
    const firstHalfEnd = 14 + dataLen / 2;
    return {
        hash: dfcHexToBytes(encoded.slice(6, 14)),
        b1: dfcHexToBytes(encoded.slice(14, firstHalfEnd)),
        b2: dfcHexToBytes(encoded.slice(firstHalfEnd)),
    };
}

// Try one passcode against one scrypt profile. Returns the decrypted bytes on a
// checksum match, else null. Pass `scratch` (dfcMakeScratch) to reuse buffers.
async function dfcTryOne(decoded, password, profile, scratch) {
    const pw = new TextEncoder().encode(password.normalize('NFKC'));
    const key = await dfcScrypt(pw, decoded.hash, profile.N, profile.r, profile.p, 64, scratch);
    const k1a = key.subarray(0, 16);
    const k1b = key.subarray(16, 32);
    const k2 = key.subarray(32, 64);
    const dec1 = await dfcAesCtrDecrypt(k2, decoded.b1);
    const dec2 = await dfcAesCtrDecrypt(k2, decoded.b2);
    const decrypted = dfcConcat(dfcXor(k1a, dec1), dfcXor(k1b, dec2));
    const chk = await dfcSha256(await dfcSha256(decrypted));
    if (dfcEq(chk.subarray(0, 4), decoded.hash)) return decrypted;
    return null;
}

/* =========================================================================
   Web Worker — built inline from the crypto functions above plus this
   bootstrap. Each worker owns a contiguous numeric sub-range and generates
   its own zero-padded codes locally.
   ========================================================================= */

const WORKER_BOOTSTRAP = `
let dfcStop = false;
self.onmessage = async function (e) {
    const m = e.data || {};
    if (m.type === 'stop') { dfcStop = true; return; }
    if (m.type === 'ping') {
        // Probe: confirms the worker runs AND that subtle crypto works here.
        try {
            await self.crypto.subtle.digest('SHA-256', new Uint8Array([0]));
            self.postMessage({ type: 'pong' });
        } catch (err) {
            self.postMessage({ type: 'error', message: 'crypto.subtle unavailable in worker' });
        }
        return;
    }
    if (m.type !== 'start') return;
    dfcStop = false;
    try {
        const decoded = dfcDecode(m.encoded);
        const profile = m.profile;
        const pad = m.pad;
        const scratch = dfcMakeScratch(profile.N, profile.r);
        let sinceReport = 0;
        for (let i = m.start; i < m.end; i++) {
            if (dfcStop) break;
            const pw = String(i).padStart(pad, '0');
            const dec = await dfcTryOne(decoded, pw, profile, scratch);
            sinceReport++;
            if (dec) {
                self.postMessage({ type: 'progress', delta: sinceReport });
                self.postMessage({ type: 'found', password: pw, decryptedHex: dfcBytesToHex(dec) });
                return;
            }
            if (sinceReport >= 16) {
                self.postMessage({ type: 'progress', delta: sinceReport });
                sinceReport = 0;
                // Yield to the event loop so a queued 'stop' message is delivered
                // (bounds Stop latency and keeps progress/ETA updating promptly).
                await new Promise(function (r) { setTimeout(r, 0); });
                if (dfcStop) break;
            }
        }
        if (sinceReport) self.postMessage({ type: 'progress', delta: sinceReport });
        self.postMessage({ type: 'done' });
    } catch (err) {
        self.postMessage({ type: 'error', message: String(err && err.message ? err.message : err) });
    }
};
`;

const WORKER_FNS = [
    dfcReadUInt32LE, dfcBlockxor, dfcRotl, dfcSalsa20_8, dfcBlockmix, dfcSmix,
    dfcMakeScratch, dfcPbkdf2, dfcScrypt, dfcSha256, dfcAesCtrDecrypt, dfcXor,
    dfcHexToBytes, dfcBytesToHex, dfcConcat, dfcEq, dfcDecode, dfcTryOne,
];

let _workerUrl = null;
function getWorkerUrl() {
    if (_workerUrl) return _workerUrl;
    const src = WORKER_FNS.map(fn => fn.toString()).join('\n\n') + '\n\n' + WORKER_BOOTSTRAP;
    const blob = new Blob([src], { type: 'application/javascript' });
    _workerUrl = URL.createObjectURL(blob);
    return _workerUrl;
}

let _workersUsable = null; // null = unknown, true/false once probed
async function workersUsable() {
    if (_workersUsable !== null) return _workersUsable;
    if (typeof Worker === 'undefined') { _workersUsable = false; return false; }
    let w = null;
    try {
        w = new Worker(getWorkerUrl());
    } catch (e) {
        _workersUsable = false;
        return false;
    }
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

/* =========================================================================
   Profiles & target parsing
   ========================================================================= */

const PROFILES = {
    mnemonic: { name: 'mnemonic', N: 16384, r: 8, p: 1, kind: 'entropy' },
    wallet: { name: 'wallet', N: 512, r: 8, p: 2, kind: 'privkey' },
};

// Extract the encode() string and detect the scheme from the input shape.
function extractTarget(raw) {
    raw = String(raw).trim();
    let detected = null;
    let encoded = null;
    let walletMeta = null;
    try {
        const j = JSON.parse(raw);
        if (j && typeof j === 'object') {
            const inner = j.raw || j;
            if (inner && inner.encryptedPrivKey) {
                encoded = String(inner.encryptedPrivKey).trim();
                detected = 'wallet';
                walletMeta = { pubKey: inner.pubKey, chainCode: inner.chainCode };
            }
        } else if (typeof j === 'string') {
            encoded = j.trim();
        }
    } catch (_) {
        /* not JSON */
    }
    if (!encoded) {
        // Raw hex string (mnemonic scheme stores the bare encode() hex).
        encoded = raw.replace(/\s+/g, '');
        detected = detected || 'mnemonic';
    }
    return { encoded, detected, walletMeta };
}

function resolveProfiles(sel, detected) {
    if (sel === 'auto') sel = detected || 'mnemonic';
    if (sel === 'both') return [PROFILES.wallet, PROFILES.mnemonic]; // cheapest first
    return [PROFILES[sel]];
}

/* =========================================================================
   BIP39 entropy → mnemonic (main thread only, uses the local wordlist)
   ========================================================================= */

async function entropyToMnemonic(entropy) {
    const wordlist = window.DEFICHAIN_BIP39;
    const ENT = entropy.length * 8;
    if (!wordlist || ![128, 160, 192, 224, 256].includes(ENT)) return null;
    const CS = ENT / 32;
    let bits = '';
    for (const b of entropy) bits += b.toString(2).padStart(8, '0');
    const csFull = await dfcSha256(entropy);
    let csBits = '';
    for (const b of csFull) csBits += b.toString(2).padStart(8, '0');
    bits += csBits.slice(0, CS);
    const words = [];
    for (let i = 0; i < bits.length; i += 11) {
        words.push(wordlist[parseInt(bits.slice(i, i + 11), 2)]);
    }
    return words.join(' ');
}

/* =========================================================================
   UI
   ========================================================================= */

const $ = id => document.getElementById(id);

const fileBtn = $('file-btn');
const fileInput = $('file-input');
const fileName = $('file-name');
const dataInput = $('data-input');
const detectTag = $('detect-tag');
const profileSelect = $('profile-select');
const digitsInput = $('digits-input');
const rangeHint = $('range-hint');
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

let running = false;
let stopRequested = false;
let activeWorkers = [];

/* MessageChannel-based yield for the main-thread fallback path. */
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

function clearOutput() { output.textContent = ''; }

function showToast(text) {
    toast.textContent = text;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2200);
}

/* ---------- helpers ---------- */
function pow10(n) { return Math.pow(10, n); }

function readDigits() {
    let d = parseInt(digitsInput.value, 10);
    if (!Number.isInteger(d) || d < 1) d = 6;
    if (d > 9) d = 9;
    return d;
}

function fmtDuration(sec) {
    if (!isFinite(sec) || sec < 0) return '?';
    sec = Math.round(sec);
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    return (h ? h + 'h ' : '') + (h || m ? m + 'm ' : '') + s + 's';
}

/* ---------- live detection tag + range hint ---------- */
function updateDetect() {
    const raw = dataInput.value.trim();
    detectTag.className = 'detect-tag';
    if (!raw) { detectTag.textContent = ''; return; }
    let target;
    try {
        target = extractTarget(raw);
        dfcDecode(target.encoded); // validate shape
    } catch (e) {
        detectTag.textContent = '✗ ' + e.message;
        detectTag.classList.add('invalid');
        return;
    }
    if (target.detected === 'wallet') {
        detectTag.textContent = '✓ Detected: wallet JSON (root key, N=512)';
        detectTag.classList.add('wallet');
    } else {
        detectTag.textContent = '✓ Detected: mnemonic scheme (raw hex, N=16384)';
        detectTag.classList.add('mnemonic');
    }
}

function updateRangeHint() {
    const d = readDigits();
    const max = pow10(d) - 1;
    const total = pow10(d);
    const minStr = '0'.repeat(d);
    const maxStr = String(max).padStart(d, '0');
    rangeHint.innerHTML = 'Will sweep <code>' + minStr + '</code> … <code>' + maxStr + '</code> (' +
        total.toLocaleString('en-US').replace(/,/g, ' ') + ' codes).';
}

dataInput.addEventListener('input', updateDetect);
digitsInput.addEventListener('input', updateRangeHint);
profileSelect.addEventListener('change', updateDetect);

/* ---------- file load ---------- */
function setFileName(text, state) {
    fileName.textContent = text;
    fileName.classList.remove('set', 'valid', 'invalid');
    if (state) fileName.classList.add(state);
}

fileBtn.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', async () => {
    const file = fileInput.files[0];
    if (!file) return;
    try {
        const text = (await file.text()).trim();
        dataInput.value = text;
        setFileName(file.name + ' (' + file.size + ' byte)', 'set');
        updateDetect();
    } catch (e) {
        setFileName('Could not read the file', 'invalid');
    }
    fileInput.value = '';
});

/* ---------- run/stop UI state ---------- */
function setRunning(state) {
    running = state;
    runBtn.classList.toggle('display-none', state);
    stopBtn.classList.toggle('display-none', !state);
    fileBtn.disabled = state;
    dataInput.disabled = state;
    profileSelect.disabled = state;
    digitsInput.disabled = state;
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
        if (f.copy !== false) {
            const btn = document.createElement('button');
            btn.className = 'copy-btn';
            btn.textContent = 'Copy';
            btn.addEventListener('click', () => {
                navigator.clipboard.writeText(f.value);
                showToast(f.label + ' copied');
            });
            valueRow.appendChild(btn);
        }
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

clearBtn.addEventListener('click', () => {
    clearOutput();
    output.textContent = 'Waiting to run…';
    progressWrap.classList.add('display-none');
    resultPanel.classList.add('display-none');
});

/* =========================================================================
   Sweep drivers
   ========================================================================= */

// Split [min, max] across Web Workers; resolve with {found, password?, decryptedHex?}.
function runSweepWorkers(encoded, profile, min, max, pad, onProgress) {
    return new Promise((resolve) => {
        const total = max - min + 1;
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
            const start = min + t * chunk;
            const end = Math.min(start + chunk, max + 1);
            if (start >= end) continue;
            const w = new Worker(getWorkerUrl());
            workers.push(w);
            w.onmessage = (e) => {
                const msg = e.data || {};
                if (settled) return;
                if (msg.type === 'progress') {
                    onProgress(msg.delta);
                } else if (msg.type === 'found') {
                    settled = true;
                    cleanup();
                    resolve({ found: true, password: msg.password, decryptedHex: msg.decryptedHex });
                } else if (msg.type === 'done') {
                    finished++;
                    if (finished >= workers.length) {
                        settled = true;
                        cleanup();
                        resolve({ found: false, stopped: stopRequested });
                    }
                } else if (msg.type === 'error') {
                    settled = true;
                    cleanup();
                    resolve({ found: false, error: msg.message });
                }
            };
            w.onerror = (err) => {
                if (settled) return;
                settled = true;
                cleanup();
                resolve({ found: false, error: (err && err.message) || 'worker error' });
            };
            w.postMessage({ type: 'start', encoded, profile, start, end, pad });
        }

        activeWorkers = workers;
        if (workers.length === 0) resolve({ found: false });
    });
}

// Single-threaded fallback on the main thread.
async function runSweepMainThread(encoded, profile, min, max, pad, onProgress) {
    const decoded = dfcDecode(encoded);
    const scratch = dfcMakeScratch(profile.N, profile.r);
    let sinceReport = 0;
    for (let i = min; i <= max; i++) {
        if (stopRequested) return { found: false, stopped: true };
        const pw = String(i).padStart(pad, '0');
        const dec = await dfcTryOne(decoded, pw, profile, scratch);
        sinceReport++;
        if (dec) { onProgress(sinceReport); return { found: true, password: pw, decryptedHex: dfcBytesToHex(dec) }; }
        if (sinceReport >= 16) { onProgress(sinceReport); sinceReport = 0; await yieldToUI(); }
    }
    if (sinceReport) onProgress(sinceReport);
    return { found: false, stopped: false };
}

/* =========================================================================
   Orchestration
   ========================================================================= */

async function run() {
    if (running) return;

    const raw = dataInput.value.trim();
    if (!raw) { showToast('Paste the encrypted string or wallet JSON first'); return; }

    let target;
    try {
        target = extractTarget(raw);
        dfcDecode(target.encoded);
    } catch (e) {
        clearOutput();
        resultPanel.classList.add('display-none');
        log('Error: ' + e.message, 'log-err');
        showToast('Invalid encrypted data');
        return;
    }

    if (typeof crypto === 'undefined' || !crypto.subtle) {
        clearOutput();
        log('Your browser lacks crypto.subtle — cannot continue.', 'log-err');
        return;
    }

    const profiles = resolveProfiles(profileSelect.value, target.detected);
    const digits = readDigits();
    const min = 0;
    const max = pow10(digits) - 1;
    const pad = Math.max(digits, String(max).length);
    const total = max - min + 1;

    stopRequested = false;
    setRunning(true);
    resultPanel.classList.add('display-none');
    progressWrap.classList.remove('display-none');
    progressBar.style.width = '0%';
    clearOutput();

    const useWorkers = await workersUsable();
    const nThreads = useWorkers ? Math.max(1, Math.min(navigator.hardwareConcurrency || 4, 16, total)) : 1;

    log('DeFiChain Light Wallet (jellyfish-wallet-encrypted)', 'log-muted');
    log('detected: ' + (target.detected || 'mnemonic') + ' (from input shape)', 'log-muted');
    log('scheme(s): ' + profiles.map(p => p.name + ' [N=' + p.N + ',r=' + p.r + ',p=' + p.p + ']').join(', '), 'log-muted');
    log('passcodes: ' + '0'.repeat(pad) + ' … ' + String(max).padStart(pad, '0') +
        '  (' + total.toLocaleString('en-US').replace(/,/g, ' ') + ' codes)', 'log-muted');
    log(useWorkers ? ('workers: ' + nThreads + ' threads') : 'workers: unavailable — running single-threaded', 'log-muted');

    const tStart = performance.now();
    let found = null;

    for (let pi = 0; pi < profiles.length; pi++) {
        if (stopRequested) break;
        const pr = profiles[pi];

        if (profiles.length > 1) {
            log('\npass ' + (pi + 1) + '/' + profiles.length + ' — scheme ' + pr.name, 'log-muted');
        }

        let done = 0;
        const t0 = performance.now();
        const onProgress = (delta) => { done += delta; };

        const timer = setInterval(() => {
            const elapsed = (performance.now() - t0) / 1000;
            const rate = done / Math.max(elapsed, 0.001);
            const remaining = total - done;
            const eta = rate > 0 ? remaining / rate : Infinity;
            const pct = Math.min(100, (done / total) * 100).toFixed(1);
            progressBar.style.width = pct + '%';
            const passLabel = profiles.length > 1 ? ('[' + pr.name + '] ') : '';
            progressStatus.textContent = passLabel + done.toLocaleString('en-US') + '/' +
                total.toLocaleString('en-US') + ' (' + pct + '%)  ' +
                Math.round(rate) + '/s  elapsed ' + fmtDuration(elapsed) + '  ETA ' + fmtDuration(eta);
        }, 300);

        let result;
        try {
            result = useWorkers
                ? await runSweepWorkers(target.encoded, pr, min, max, pad, onProgress)
                : await runSweepMainThread(target.encoded, pr, min, max, pad, onProgress);
        } catch (e) {
            result = { found: false, error: (e && e.message) || String(e) };
        }

        clearInterval(timer);

        if (result.error) {
            log('\nError during sweep: ' + result.error, 'log-err');
            progressBar.style.width = '0%';
            progressStatus.textContent = 'Error';
            setRunning(false);
            return;
        }

        if (result.found) {
            found = { password: result.password, decryptedHex: result.decryptedHex, profile: pr };
            progressBar.style.width = '100%';
            break;
        }

        if (result.stopped || stopRequested) break;
    }

    const secs = ((performance.now() - tStart) / 1000).toFixed(1);

    if (found) {
        progressStatus.textContent = 'Done — passcode found (' + secs + 's)';
        await presentResult(found, target.walletMeta);
    } else if (stopRequested) {
        progressStatus.textContent = 'Stopped (' + secs + 's)';
        log('\nStopped by the user.', 'log-err');
    } else {
        progressStatus.textContent = 'Done — no matching passcode (' + secs + 's)';
        log('\n✗ No passcode in the swept range matched.', 'log-err');
        showResult(false, '✗ No matching passcode', [
            {
                label: 'Result',
                value: 'Swept ' + total.toLocaleString('en-US') + ' codes with no match. If you pasted a bare wallet ' +
                    'key as raw hex, try scheme "Both"; if the passcode is not ' + digits + (digits === 1 ? ' digit' : ' digits') +
                    ', change the length.',
                copy: false,
            },
        ]);
    }

    setRunning(false);
}

async function presentResult(found, walletMeta) {
    const dec = dfcHexToBytes(found.decryptedHex);
    log('\n✓ MATCH — passcode: ' + found.password, 'log-hit');
    log('scheme: ' + found.profile.name + ' (' + found.profile.kind + ')', 'log-ok');

    const fields = [{ label: 'Passcode', value: found.password }];

    if (found.profile.kind === 'entropy') {
        log('entropy: ' + found.decryptedHex, 'log-ok');
        fields.push({ label: 'BIP39 entropy', value: found.decryptedHex });
        const mnemonic = await entropyToMnemonic(dec);
        if (mnemonic) {
            log('\nmnemonic:\n' + mnemonic, 'log-ok');
            fields.push({ label: 'Seed phrase (mnemonic)', value: mnemonic });
            showResult(true, '✓ Wallet unlocked!', fields);
        } else {
            log('(decrypted data is ' + dec.length + ' bytes — not a standard BIP39 entropy length)', 'log-muted');
            fields.push({
                label: 'Note',
                value: 'Decrypted ' + dec.length + ' bytes, which is not a standard BIP39 entropy length.',
                copy: false,
            });
            showResult(true, '✓ Passcode found', fields);
        }
    } else {
        log('root privKey: ' + found.decryptedHex, 'log-ok');
        fields.push({ label: 'BIP32 root private key', value: found.decryptedHex });
        if (walletMeta && walletMeta.pubKey) {
            log('pubKey: ' + walletMeta.pubKey, 'log-ok');
            fields.push({ label: 'Public key', value: walletMeta.pubKey });
        }
        if (walletMeta && walletMeta.chainCode) {
            log('chainCode: ' + walletMeta.chainCode, 'log-ok');
            fields.push({ label: 'Chain code', value: walletMeta.chainCode });
        }
        fields.push({
            label: 'Note',
            value: 'This is the BIP32 root private key. It does not contain the mnemonic words, but together ' +
                'with the chain code it can derive every address/key in the wallet.',
            copy: false,
        });
        showResult(true, '✓ Wallet unlocked!', fields);
    }
}

/* ---------- init ---------- */
updateRangeHint();

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
