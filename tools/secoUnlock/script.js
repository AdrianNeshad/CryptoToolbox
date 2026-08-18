/* =========================================================================
   SECO decrypt-kärna — porterad byte-för-byte från de node-paket som
   originalskriptet (secoUnlock) använder:
     seco-file / secure-container  → filformat + AES-256-GCM
     scryptsy                      → scrypt (nyckelsträckning)
     bitcoin-seed + bip39          → entropy → mnemonic
   Körs helt lokalt via WebCrypto (crypto.subtle) + DecompressionStream.
   ========================================================================= */

/* ---------- scrypt (port av scryptsy) ---------- */

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
    if ((N & (N - 1)) !== 0 || N === 0) throw new Error('N måste vara en potens av 2');
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

/* ---------- SECO-fil-parsning ---------- */

function parseSeco(fileBytes) {
    // header(224) checksum(32) metadata(256) blobLen(UInt32BE) blob(blobLen)
    if (fileBytes.length < 224 + 32 + 256 + 4) {
        throw new Error('Filen är för liten för att vara en giltig .seco-fil.');
    }
    const magic = String.fromCharCode(fileBytes[0], fileBytes[1], fileBytes[2], fileBytes[3]);
    if (magic !== 'SECO') {
        throw new Error('Ogiltig fil: saknar "SECO"-signatur. Är detta verkligen en seed.seco-fil?');
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

/* ---------- dekryptera med ETT lösenord (kastar vid fel lösenord) ---------- */

async function tryPassword(parsed, password, wordlist) {
    const { meta, blob } = parsed;
    const pwBytes = new TextEncoder().encode(password);
    const derivedKey = await scrypt(pwBytes, meta.salt, meta.n, meta.r, meta.p, 32);
    // GCM-auth misslyckas → fel lösenord → kastar OperationError
    const blobKey = await aesGcmDecrypt(derivedKey, meta.blobKey.key, meta.blobKey.iv, meta.blobKey.authTag);
    const data = await aesGcmDecrypt(blobKey, blob, meta.blob.iv, meta.blob.authTag);
    // shrink: UInt32BE(0) = t, slice(4, t+4)
    const t = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0, false);
    const shrinked = data.subarray(4, 4 + t);
    const gunzipped = await gunzip(shrinked);
    const rest = gunzipped.subarray(64);
    if (rest.length === 16 || rest.length === 32) {
        return entropyToMnemonic(rest, wordlist);
    }
    return new TextDecoder().decode(rest);
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
const testdataBtn = $('testdata-btn');
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

/* MessageChannel-baserad yield: släpper fram en repaint mellan lösenord
   utan setTimeout(0):s ~4 ms-klämma. */
const _mc = new MessageChannel();
let _yieldResolve = null;
_mc.port1.onmessage = () => { if (_yieldResolve) { const r = _yieldResolve; _yieldResolve = null; r(); } };
function yieldToUI() {
    return new Promise(resolve => { _yieldResolve = resolve; _mc.port2.postMessage(0); });
}

/* ---------- output-logg ---------- */

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

/* ---------- lösenordsräknare ---------- */

function parsePasswords() {
    return pwList.value.split('\n').map(p => p.trim()).filter(p => p.length > 0);
}

function updatePwCount() {
    const n = parsePasswords().length;
    pwCount.textContent = n > 0 ? `${n} lösenord` : '';
}

pwList.addEventListener('input', updatePwCount);

/* ---------- filval ---------- */

function setSecoName(text, state, title) {
    secoName.textContent = text;
    secoName.classList.remove('set', 'valid', 'invalid');
    if (state) secoName.classList.add(state);
    if (title) secoName.title = title; else secoName.removeAttribute('title');
}

function applySecoBytes(buf, label) {
    secoBytes = new Uint8Array(buf);
    // Validera signatur/storlek → grön text om giltig, röd om inte
    try {
        parseSeco(secoBytes);
        setSecoName(label, 'valid', 'Giltig .seco-fil');
    } catch (e) {
        setSecoName(label, 'invalid', 'Ogiltig .seco-fil: ' + e.message);
    }
}

function applyPasswordText(text, label) {
    pwList.value = text;
    pwName.textContent = label;
    pwName.classList.add('set');
    updatePwCount();
}

secoBtn.addEventListener('click', () => secoInput.click());

secoInput.addEventListener('change', async () => {
    const file = secoInput.files[0];
    if (!file) return;
    try {
        const buf = await file.arrayBuffer();
        applySecoBytes(buf, `${file.name} (${buf.byteLength} byte)`);
    } catch (e) {
        secoBytes = null;
        setSecoName('Kunde inte läsa filen', null);
    }
});

pwBtn.addEventListener('click', () => pwInput.click());

pwInput.addEventListener('change', async () => {
    const file = pwInput.files[0];
    if (!file) return;
    try {
        applyPasswordText(await file.text(), file.name);
    } catch (e) {
        pwName.textContent = 'Kunde inte läsa filen';
        pwName.classList.remove('set');
    }
});

testdataBtn.addEventListener('click', async () => {
    if (running) return;
    testdataBtn.disabled = true;
    try {
        const [secoRes, pwRes] = await Promise.all([
            fetch('test/seed.seco'),
            fetch('test/passwords.txt'),
        ]);
        if (!secoRes.ok || !pwRes.ok) throw new Error('Testfilerna kunde inte hämtas.');
        const buf = await secoRes.arrayBuffer();
        applySecoBytes(buf, `seed.seco (${buf.byteLength} byte, testdata)`);
        applyPasswordText(await pwRes.text(), 'passwords.txt (testdata)');
        showToast('Testdata inläst');
    } catch (e) {
        showToast('Kunde inte läsa testdata: ' + e.message);
    } finally {
        testdataBtn.disabled = false;
    }
});

/* ---------- körning ---------- */

function setRunning(state) {
    running = state;
    runBtn.classList.toggle('display-none', state);
    stopBtn.classList.toggle('display-none', !state);
    secoBtn.disabled = state;
    pwBtn.disabled = state;
    pwList.disabled = state;
    testdataBtn.disabled = state;
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
        btn.textContent = 'Kopiera';
        btn.addEventListener('click', () => {
            navigator.clipboard.writeText(f.value);
            showToast(f.label + ' kopierad');
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
    progressStatus.textContent = 'Stoppar…';
});

async function run() {
    if (running) return;

    if (!secoBytes) { showToast('Välj en .seco-fil först'); return; }
    const passwords = parsePasswords();
    if (passwords.length === 0) { showToast('Lägg till minst ett lösenord'); return; }

    if (typeof DecompressionStream === 'undefined') {
        clearOutput();
        log('Din webbläsare saknar stöd för DecompressionStream (gzip) — kan inte fortsätta.', 'log-err');
        return;
    }

    const wordlist = window.entropyWordlists.bip39;

    // Parsa .seco-filen
    let parsed;
    try {
        parsed = parseSeco(secoBytes);
    } catch (e) {
        clearOutput();
        resultPanel.classList.add('display-none');
        log('Fel: ' + e.message, 'log-err');
        return;
    }

    stopRequested = false;
    setRunning(true);
    resultPanel.classList.add('display-none');
    progressWrap.classList.remove('display-none');
    progressBar.style.width = '0%';
    clearOutput();
    log(`scrypt-parametrar: N=${parsed.meta.n}, r=${parsed.meta.r}, p=${parsed.meta.p}`, 'log-muted');
    log(`Testar ${passwords.length} lösenord…`, 'log-muted');

    const total = passwords.length;
    const t0 = performance.now();
    let found = null;

    for (let i = 0; i < total; i++) {
        if (stopRequested) {
            log(`\nStoppad av användaren vid ${i} av ${total}.`, 'log-err');
            break;
        }

        const pw = passwords[i];
        progressStatus.textContent = `[${i + 1}/${total}] testar: ${pw}`;
        progressBar.style.width = ((i / total) * 100).toFixed(1) + '%';
        await yieldToUI();

        try {
            const mnemonic = await tryPassword(parsed, pw, wordlist);
            found = { password: pw, mnemonic, index: i + 1 };
            break;
        } catch (e) {
            // OperationError = fel lösenord; annat = oväntat fel
            if (e && e.name !== 'OperationError') {
                log(`  [${i + 1}] "${pw}" → oväntat fel: ${e.message}`, 'log-err');
            }
        }
    }

    progressBar.style.width = '100%';
    const secs = ((performance.now() - t0) / 1000).toFixed(1);

    if (found) {
        progressStatus.textContent = `Klar — lösenord hittat på försök ${found.index} av ${total} (${secs}s)`;
        log(`\n✓ MATCH på lösenord #${found.index}: ${found.password}`, 'log-hit');
        log(`Mnemonic: ${found.mnemonic}`, 'log-ok');
        showResult(true, '✓ Lösenord hittat!', [
            { label: 'Lösenord', value: found.password },
            { label: 'Seed-fras (mnemonic)', value: found.mnemonic },
        ]);
    } else if (stopRequested) {
        progressStatus.textContent = `Stoppad (${secs}s)`;
    } else {
        progressStatus.textContent = `Klar — inget matchande lösenord (${secs}s)`;
        log(`\n✗ Inget av de ${total} lösenorden matchade.`, 'log-err');
        showResult(false, '✗ Inget matchande lösenord', [
            { label: 'Resultat', value: `Testade ${total} lösenord utan träff. Kontrollera listan eller lägg till fler.` },
        ]);
    }

    setRunning(false);
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
