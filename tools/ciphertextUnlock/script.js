/* =========================================================================
   Ciphertext Unlock — porterad från ciphertextUnlock (Node).
   Multi-format-dekryptor som körs helt lokalt via WebCrypto, BigInt (keccak256)
   och en ren-JS scrypt. Stödjer:
     • Ethereum / TrustWallet V3  (scrypt + AES-128-CTR + keccak256-MAC)
     • CryptoJS                   (PBKDF2 gissas + AES-CBC)
     • PBKDF2-vault               (PBKDF2 + AES-256-GCM/CBC)
     • Generic AES                (PBKDF2 + AES-256-CTR, ingen MAC)
   ========================================================================= */

/* ---------- hjälpare ---------- */
function utf8(s) { return new TextEncoder().encode(s); }
function hexToBytes(hex) {
    const clean = String(hex).trim();
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
}
function bytesToHex(bytes) {
    let s = '';
    for (const b of bytes) s += b.toString(16).padStart(2, '0');
    return s;
}
function b64ToBytes(b64) {
    const bin = atob(String(b64).trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
}

/* ---------- keccak-256 (Ethereum, domän 0x01) ---------- */
const _MASK64 = (1n << 64n) - 1n;
const _RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const _ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const _PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

function _rotl(x, n) { const b = BigInt(n); return ((x << b) | (x >> (64n - b))) & _MASK64; }

function _keccakf(st) {
    const bc = new Array(5);
    for (let round = 0; round < 24; round++) {
        for (let i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (let i = 0; i < 5; i++) {
            const t = bc[(i + 4) % 5] ^ _rotl(bc[(i + 1) % 5], 1);
            for (let j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        let t = st[1];
        for (let i = 0; i < 24; i++) {
            const j = _PILN[i];
            const tmp = st[j];
            st[j] = _rotl(t, _ROTC[i]);
            t = tmp;
        }
        for (let j = 0; j < 25; j += 5) {
            for (let i = 0; i < 5; i++) bc[i] = st[j + i];
            for (let i = 0; i < 5; i++) st[j + i] ^= (bc[(i + 1) % 5] ^ _MASK64) & bc[(i + 2) % 5];
        }
        st[0] ^= _RC[round];
    }
}
function _load64(b, off) { let x = 0n; for (let i = 7; i >= 0; i--) x = (x << 8n) | BigInt(b[off + i]); return x; }
function _store64(b, off, x) { for (let i = 0; i < 8; i++) { b[off + i] = Number(x & 0xffn); x >>= 8n; } }

function keccak256(msg) {
    const rate = 136;
    const st = new Array(25).fill(0n);
    const len = msg.length;
    let offset = 0;
    while (len - offset >= rate) {
        for (let i = 0; i < rate; i += 8) st[i / 8] ^= _load64(msg, offset + i);
        _keccakf(st);
        offset += rate;
    }
    const block = new Uint8Array(rate);
    block.set(msg.subarray(offset), 0);
    block[len - offset] ^= 0x01;
    block[rate - 1] ^= 0x80;
    for (let i = 0; i < rate; i += 8) st[i / 8] ^= _load64(block, i);
    _keccakf(st);
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i += 8) _store64(out, i, st[i / 8]);
    return out;
}

/* ---------- scrypt (port av scryptsy) ---------- */
function readUInt32LE(a, o) { return ((a[o]) | (a[o + 1] << 8) | (a[o + 2] << 16) | (a[o + 3] << 24)); }
function blockxor(S, Si, D, Di, len) { for (let i = 0; i < len; i++) D[Di + i] ^= S[Si + i]; }
function R(a, b) { return (a << b) | (a >>> (32 - b)); }
function salsa20_8(B, B32, x) {
    let i;
    for (i = 0; i < 16; i++) {
        B32[i] = (B[i * 4 + 0] & 0xff) << 0; B32[i] |= (B[i * 4 + 1] & 0xff) << 8;
        B32[i] |= (B[i * 4 + 2] & 0xff) << 16; B32[i] |= (B[i * 4 + 3] & 0xff) << 24;
    }
    for (i = 0; i < 16; i++) x[i] = B32[i];
    for (i = 8; i > 0; i -= 2) {
        x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9); x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
        x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9); x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
        x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9); x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
        x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9); x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
        x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9); x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
        x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9); x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
        x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9); x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
        x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9); x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
    }
    for (i = 0; i < 16; ++i) B32[i] = x[i] + B32[i];
    for (i = 0; i < 16; i++) {
        const bi = i * 4;
        B[bi + 0] = (B32[i] >> 0 & 0xff); B[bi + 1] = (B32[i] >> 8 & 0xff);
        B[bi + 2] = (B32[i] >> 16 & 0xff); B[bi + 3] = (B32[i] >> 24 & 0xff);
    }
}
function blockmix_salsa8(BY, Bi, Yi, r, _X, B32, x) {
    let i;
    _X.set(BY.subarray(Bi + (2 * r - 1) * 64, Bi + (2 * r - 1) * 64 + 64), 0);
    for (i = 0; i < 2 * r; i++) { blockxor(BY, i * 64, _X, 0, 64); salsa20_8(_X, B32, x); BY.set(_X.subarray(0, 64), Yi + (i * 64)); }
    for (i = 0; i < r; i++) BY.set(BY.subarray(Yi + (i * 2) * 64, Yi + (i * 2) * 64 + 64), Bi + (i * 64));
    for (i = 0; i < r; i++) BY.set(BY.subarray(Yi + (i * 2 + 1) * 64, Yi + (i * 2 + 1) * 64 + 64), Bi + (i + r) * 64);
}
function smixSync(B, Bi, r, N, V, XY, _X, B32, x) {
    const Xi = 0, Yi = 128 * r;
    XY.set(B.subarray(Bi, Bi + Yi), Xi);
    for (let i = 0; i < N; i++) { V.set(XY.subarray(Xi, Xi + Yi), i * Yi); blockmix_salsa8(XY, Xi, Yi, r, _X, B32, x); }
    for (let i = 0; i < N; i++) {
        const j = readUInt32LE(XY, Xi + (2 * r - 1) * 64) & (N - 1);
        blockxor(V, j * Yi, XY, Xi, Yi); blockmix_salsa8(XY, Xi, Yi, r, _X, B32, x);
    }
    B.set(XY.subarray(Xi, Xi + Yi), Bi);
}
async function scrypt(passwordBytes, saltBytes, N, r, p, dkLen) {
    if ((N & (N - 1)) !== 0 || N === 0) throw new Error('N måste vara en potens av 2');
    const XY = new Uint8Array(256 * r), V = new Uint8Array(128 * r * N);
    const B32 = new Int32Array(16), x = new Int32Array(16), _X = new Uint8Array(64);
    const B = await pbkdf2(passwordBytes, saltBytes, 1, p * 128 * r, 'SHA-256');
    for (let i = 0; i < p; i++) smixSync(B, i * 128 * r, r, N, V, XY, _X, B32, x);
    return pbkdf2(passwordBytes, B, 1, dkLen, 'SHA-256');
}

/* ---------- WebCrypto-primitiver ---------- */
async function pbkdf2(pwBytes, saltBytes, iterations, dkLen, hash) {
    const key = await crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash, salt: saltBytes, iterations }, key, dkLen * 8);
    return new Uint8Array(bits);
}
async function aesCtrDecrypt(data, key, iv) {
    const k = await crypto.subtle.importKey('raw', key, { name: 'AES-CTR' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 128 }, k, data);
    return new Uint8Array(pt);
}
async function aesCbcDecrypt(data, key, iv) {
    const k = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, k, data);
    return new Uint8Array(pt);
}
async function aesGcmDecrypt(data, key, iv, authTag) {
    const k = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, concatBytes(data, authTag));
    return new Uint8Array(pt);
}

/* ---------- wallet-format ---------- */
async function decryptEthereum(wallet, password) {
    const c = wallet.crypto || wallet.Crypto;
    const kp = c.kdfparams;
    const key = await scrypt(utf8(password), hexToBytes(kp.salt), kp.n, kp.r, kp.p, kp.dklen);
    const ciphertext = hexToBytes(c.ciphertext);
    const mac = bytesToHex(keccak256(concatBytes(key.subarray(16, 32), ciphertext)));
    if (mac !== String(c.mac).toLowerCase()) throw new Error('Fel MAC');
    const iv = hexToBytes(c.cipherparams.iv);
    return aesCtrDecrypt(ciphertext, key.subarray(0, 16), iv);
}

async function decryptKeyMetadataVault(wallet, password) {
    const salt = b64ToBytes(wallet.salt);
    const iv = hexToBytes(wallet.iv);
    const raw = b64ToBytes(wallet.cipher);
    const iterations = wallet.keyMetadata.params.iterations;
    const key = await pbkdf2(utf8(password), salt, iterations, 32, 'SHA-256');
    try {
        const authTag = raw.subarray(raw.length - 16);
        const ciphertext = raw.subarray(0, raw.length - 16);
        return await aesGcmDecrypt(ciphertext, key, iv, authTag);
    } catch (err) {
        return aesCbcDecrypt(raw, key, iv);
    }
}

const _KEY_SIZES = [16, 32];
const _ITERATIONS = [1, 1000, 2048, 5000, 10000, 100000];
const _HASHES = ['SHA-1', 'SHA-256'];
function isMostlyPrintable(buf) {
    if (buf.length === 0) return false;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
    let printable = 0;
    for (const ch of text) {
        const code = ch.charCodeAt(0);
        if ((code >= 0x20 && code <= 0x7e) || code === 0x0a || code === 0x0d || code === 0x09) printable++;
    }
    return printable / text.length > 0.9;
}
async function decryptCryptoJS(wallet, password) {
    const salt = b64ToBytes(wallet.salt);
    const iv = hexToBytes(wallet.iv);
    const ciphertext = b64ToBytes(wallet.cipher);
    for (const keySize of _KEY_SIZES) {
        for (const iterations of _ITERATIONS) {
            for (const hash of _HASHES) {
                const key = await pbkdf2(utf8(password), salt, iterations, keySize, hash);
                try {
                    const decrypted = await aesCbcDecrypt(ciphertext, key, iv);
                    if (isMostlyPrintable(decrypted)) return decrypted;
                } catch (err) { /* fel paddning -> nästa kombination */ }
            }
        }
    }
    throw new Error('Fel lösenord');
}

async function decryptGeneric(wallet, password) {
    const kp = wallet.kdf;
    const key = await pbkdf2(utf8(password), hexToBytes(kp.salt), kp.iterations, kp.dklen, 'SHA-256');
    return aesCtrDecrypt(hexToBytes(wallet.encrypted_seed), key, hexToBytes(wallet.iv));
}

function detectFormat(wallet) {
    if (wallet.cipher && wallet.iv && wallet.salt && wallet.keyMetadata && wallet.keyMetadata.algorithm === 'PBKDF2') {
        return { name: 'PBKDF2-vault', decrypt: decryptKeyMetadataVault, verified: true };
    }
    if (wallet.cipher && wallet.iv && wallet.salt && !wallet.crypto && !wallet.Crypto) {
        return { name: 'CryptoJS', decrypt: decryptCryptoJS, verified: true };
    }
    const c = wallet.crypto || wallet.Crypto;
    if (!c) throw new Error('Ingen crypto-struktur hittades (crypto/Crypto, eller cipher+iv+salt).');
    if (c.cipher && String(c.cipher).toLowerCase() === 'aes-128-ctr' && c.kdf === 'scrypt') {
        return { name: 'Ethereum / TrustWallet V3', decrypt: decryptEthereum, verified: true };
    }
    return { name: 'Generic AES', decrypt: decryptGeneric, verified: false };
}

/* =========================================================================
   UI
   ========================================================================= */
const $ = id => document.getElementById(id);

const jsonBtn = $('json-btn');
const jsonFileInput = $('json-file-input');
const jsonFileName = $('json-file-name');
const jsonInput = $('json-input');
const detectStatus = $('detect-status');
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

let parsedWallet = null;
let detector = null;
let running = false;
let stopRequested = false;

/* MessageChannel-baserad yield: släpper fram en repaint mellan lösenord. */
const _mc = new MessageChannel();
let _yieldResolve = null;
_mc.port1.onmessage = () => { if (_yieldResolve) { const r = _yieldResolve; _yieldResolve = null; r(); } };
function yieldToUI() { return new Promise(resolve => { _yieldResolve = resolve; _mc.port2.postMessage(0); }); }

/* ---------- output-logg ---------- */
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
function cleanText(str) { return str.replace(/[^\x20-\x7E\n\r\t]/g, '').trim(); }

/* ---------- lösenordsräknare ---------- */
function parsePasswords() { return pwList.value.split('\n').map(p => p.trim()).filter(p => p.length > 0); }
function updatePwCount() {
    const n = parsePasswords().length;
    pwCount.textContent = n > 0 ? `${n} lösenord` : '';
}
pwList.addEventListener('input', updatePwCount);

/* ---------- JSON-inmatning + formatdetektering ---------- */
function setDetectStatus(text, state) {
    detectStatus.textContent = text;
    detectStatus.classList.remove('display-none', 'valid', 'invalid');
    if (state) detectStatus.classList.add(state);
    if (!text) detectStatus.classList.add('display-none');
}

function validateJson() {
    parsedWallet = null;
    detector = null;
    const raw = jsonInput.value.trim();
    if (!raw) { setDetectStatus('', null); return; }
    let obj;
    try {
        obj = JSON.parse(raw);
    } catch (e) {
        setDetectStatus('✗ Ogiltig JSON: ' + e.message, 'invalid');
        return;
    }
    try {
        const det = detectFormat(obj);
        parsedWallet = obj;
        detector = det;
        const note = det.verified ? '' : ' (obs: inget MAC/verifieringssteg — resultatet kan bli felaktigt vid fel lösenord)';
        setDetectStatus(`✓ Igenkänt format: ${det.name}${note}`, 'valid');
    } catch (e) {
        setDetectStatus('✗ ' + e.message, 'invalid');
    }
}
jsonInput.addEventListener('input', validateJson);

jsonBtn.addEventListener('click', () => jsonFileInput.click());
jsonFileInput.addEventListener('change', async () => {
    const file = jsonFileInput.files[0];
    if (!file) return;
    try {
        jsonInput.value = (await file.text()).trim();
        jsonFileName.textContent = file.name;
        jsonFileName.classList.add('set');
        validateJson();
    } catch (e) {
        jsonFileName.textContent = 'Kunde inte läsa filen';
        jsonFileName.classList.remove('set');
    }
});

pwBtn.addEventListener('click', () => pwInput.click());
pwInput.addEventListener('change', async () => {
    const file = pwInput.files[0];
    if (!file) return;
    try {
        pwList.value = await file.text();
        pwName.textContent = file.name;
        pwName.classList.add('set');
        updatePwCount();
    } catch (e) {
        pwName.textContent = 'Kunde inte läsa filen';
        pwName.classList.remove('set');
    }
});

/* ---------- körning ---------- */
function setRunning(state) {
    running = state;
    runBtn.classList.toggle('display-none', state);
    stopBtn.classList.toggle('display-none', !state);
    jsonBtn.disabled = state;
    pwBtn.disabled = state;
    pwList.disabled = state;
    jsonInput.disabled = state;
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
            btn.textContent = 'Kopiera';
            btn.addEventListener('click', () => {
                navigator.clipboard.writeText(f.value);
                showToast(f.label + ' kopierad');
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
    progressStatus.textContent = 'Stoppar…';
});

async function run() {
    if (running) return;
    validateJson();
    if (!parsedWallet || !detector) { showToast('Klistra in en giltig krypterad JSON först'); return; }
    const passwords = parsePasswords();
    if (passwords.length === 0) { showToast('Lägg till minst ett lösenord'); return; }

    stopRequested = false;
    setRunning(true);
    resultPanel.classList.add('display-none');
    progressWrap.classList.remove('display-none');
    progressBar.style.width = '0%';
    clearOutput();
    log(`Format: ${detector.name}`, 'log-muted');
    if (!detector.verified) log('Obs: detta format saknar MAC/verifiering — kontrollera att resultatet ser rimligt ut.', 'log-err');
    log(`Testar ${passwords.length} lösenord…`, 'log-muted');

    const total = passwords.length;
    const t0 = performance.now();
    let found = null;

    for (let i = 0; i < total; i++) {
        if (stopRequested) { log(`\nStoppad av användaren vid ${i} av ${total}.`, 'log-err'); break; }
        const pw = passwords[i];
        progressStatus.textContent = `[${i + 1}/${total}] testar: ${pw}`;
        progressBar.style.width = ((i / total) * 100).toFixed(1) + '%';
        await yieldToUI();
        try {
            const res = await detector.decrypt(parsedWallet, pw);
            found = { password: pw, bytes: res, index: i + 1 };
            break;
        } catch (e) {
            // fel lösenord (MAC/paddning) — fortsätt
        }
    }

    progressBar.style.width = '100%';
    const secs = ((performance.now() - t0) / 1000).toFixed(1);

    if (found) {
        progressStatus.textContent = `Klar — lösenord hittat på försök ${found.index} av ${total} (${secs}s)`;
        presentResult(found.password, found.bytes, found.index);
    } else if (stopRequested) {
        progressStatus.textContent = `Stoppad (${secs}s)`;
    } else {
        progressStatus.textContent = `Klar — inget matchande lösenord (${secs}s)`;
        log(`\n✗ Inget av de ${total} lösenorden matchade.`, 'log-err');
        showResult(false, '✗ Inget matchande lösenord', [
            { label: 'Resultat', value: `Testade ${total} lösenord utan träff. Kontrollera JSON:en och listan.`, copy: false },
        ]);
    }
    setRunning(false);
}

function presentResult(password, bytes, index) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const cleaned = cleanText(text);
    const hex = bytesToHex(bytes);

    log(`\n✓ MATCH på lösenord #${index}: ${password}`, 'log-hit');
    log(`\nDekrypterat (text): ${cleaned}`, 'log-ok');
    log(`Hex: ${hex}`, 'log-ok');

    const fields = [
        { label: 'Lösenord', value: password },
        { label: 'Format', value: detector.name, copy: false },
    ];
    if (cleaned) fields.push({ label: 'Dekrypterat (text)', value: cleaned });
    else fields.push({ label: 'Dekrypterat', value: '(inget läsbart innehåll — se HEX nedan)', copy: false });
    fields.push({ label: 'HEX', value: hex });

    showResult(true, '✓ Dekryptering lyckades!', fields);
}

clearBtn.addEventListener('click', () => {
    clearOutput();
    output.textContent = 'Väntar på körning…';
    progressWrap.classList.add('display-none');
    resultPanel.classList.add('display-none');
});

/* ---------- temasynk med Verktygslådan ---------- */
window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    var data = event.data;
    if (data && data.source === 'verktygslada' && data.type === 'theme' &&
        (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignoreras */ }
    }
});
