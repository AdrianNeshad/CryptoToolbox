/* =========================================================================
   Electrum wallet decrypt core — ported from electrumUnlock/main.py.
   Runs fully locally via WebCrypto (crypto.subtle), BigInt (secp256k1), and
   DecompressionStream. No BIP39 wordlist is needed: Electrum stores
   the seed phrase as (encrypted) text, not as entropy.

   Layers:
     1. Outer: BIE1-ECIES (secp256k1 + AES-128-CBC + HMAC-SHA256) → zlib → JSON
     2. Inner: keystore['seed']/['passphrase'] = base64(iv + AES-256-CBC),
               key = SHA256(SHA256(password))
   ========================================================================= */

/* ---------- helpers ---------- */
function utf8(s) { return new TextEncoder().encode(s); }

function b64decode(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function bytesToBigIntBE(bytes) {
    let x = 0n;
    for (const b of bytes) x = (x << 8n) | BigInt(b);
    return x;
}

function bigIntTo32BE(x) {
    const out = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    return out;
}

function ctEqual(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
}

/* ---------- secp256k1 ---------- */
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

function mod(a, m) { const r = a % m; return r < 0n ? r + m : r; }

function modpow(base, exp, m) {
    base = mod(base, m);
    let result = 1n;
    while (exp > 0n) {
        if (exp & 1n) result = (result * base) % m;
        base = (base * base) % m;
        exp >>= 1n;
    }
    return result;
}

function inv(a, m) { return modpow(a, m - 2n, m); }

function pointAdd(p1, p2) {
    if (p1 === null) return p2;
    if (p2 === null) return p1;
    const [x1, y1] = p1, [x2, y2] = p2;
    if (x1 === x2 && mod(y1 + y2, P) === 0n) return null;
    let lam;
    if (x1 === x2 && y1 === y2) {
        lam = mod(3n * x1 * x1 * inv(2n * y1, P), P);
    } else {
        lam = mod((y2 - y1) * inv(mod(x2 - x1, P), P), P);
    }
    const x3 = mod(lam * lam - x1 - x2, P);
    const y3 = mod(lam * (x1 - x3) - y1, P);
    return [x3, y3];
}

function scalarMult(k, point) {
    let result = null;
    let addend = point;
    while (k > 0n) {
        if (k & 1n) result = pointAdd(result, addend);
        addend = pointAdd(addend, addend);
        k >>= 1n;
    }
    return result;
}

function decompressPubkey(data) {
    const prefix = data[0];
    const x = bytesToBigIntBE(data.subarray(1, 33));
    const ySq = mod(modpow(x, 3n, P) + 7n, P);
    let y = modpow(ySq, (P + 1n) / 4n, P);
    if ((y % 2n === 0n) !== (prefix === 2)) y = P - y;
    return [x, y];
}

function compressPubkey(point) {
    const [x, y] = point;
    const out = new Uint8Array(33);
    out[0] = (y % 2n === 0n) ? 2 : 3;
    out.set(bigIntTo32BE(x), 1);
    return out;
}

/* ---------- WebCrypto primitives ---------- */
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
async function sha512(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-512', bytes)); }

async function hmacSha256(keyBytes, data) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

async function aesCbcDecrypt(keyBytes, ciphertext, iv) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ciphertext);
    return new Uint8Array(pt);
}

async function pbkdf2Sha512(pwBytes, saltBytes, iterations, dkLen) {
    const key = await crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-512', salt: saltBytes, iterations }, key, dkLen * 8);
    return new Uint8Array(bits);
}

async function inflate(bytes) {
    const ds = new DecompressionStream('deflate');
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    return new Uint8Array(await new Response(stream).arrayBuffer());
}

/* ---------- Electrum logic ---------- */
async function getEckeyFromPassword(password) {
    const secret = await pbkdf2Sha512(utf8(password), new Uint8Array(0), 1024, 64);
    return mod(bytesToBigIntBE(secret), N);
}

// Returns plaintext (Uint8Array) or null on a MAC error (wrong password).
async function eciesDecrypt(d, raw) {
    const ephem = raw.subarray(4, 37);
    const ciphertext = raw.subarray(37, raw.length - 32);
    const macRecv = raw.subarray(raw.length - 32);

    const ephemPoint = decompressPubkey(ephem);
    const shared = scalarMult(d, ephemPoint);
    const km = await sha512(compressPubkey(shared));
    const iv = km.subarray(0, 16), keyE = km.subarray(16, 32), keyM = km.subarray(32, 64);

    const macData = raw.subarray(0, raw.length - 32);
    const macCalc = await hmacSha256(keyM, macData);
    if (!ctEqual(macCalc, macRecv)) return null;

    return aesCbcDecrypt(keyE, ciphertext, iv);
}

function checkMagic(rawContent) {
    const raw = b64decode(rawContent);
    const magic = String.fromCharCode(raw[0] || 0, raw[1] || 0, raw[2] || 0, raw[3] || 0);
    return { raw, magic };
}

// Returns JSON text on the correct password, null on a wrong password. Throws on a format error.
async function decryptWalletFile(raw, password) {
    const d = await getEckeyFromPassword(password);
    const plaintext = await eciesDecrypt(d, raw);
    if (plaintext === null) return null; // wrong password (MAC error)
    const jsonBytes = await inflate(plaintext);
    return new TextDecoder().decode(jsonBytes);
}

// Inner field encryption (seed/passphrase): key = SHA256(SHA256(pw)), base64(iv[16] + AES-256-CBC).
async function pwDecode(encodedStr, password) {
    const secret = await sha256(await sha256(utf8(password)));
    const raw = b64decode(encodedStr);
    if (raw.length < 32) throw new Error('too short');
    const iv = raw.subarray(0, 16), ct = raw.subarray(16);
    const pt = await aesCbcDecrypt(secret, ct, iv);
    return new TextDecoder().decode(pt);
}

function collectKeystores(data) {
    const ks = [];
    if (data.keystore) ks.push(['keystore', data.keystore]);
    for (const [k, v] of Object.entries(data)) {
        if (k.startsWith('x') && k.endsWith('/') && v && typeof v === 'object') ks.push([k, v]);
    }
    return ks;
}

/* =========================================================================
   UI
   ========================================================================= */

const $ = id => document.getElementById(id);

const walletBtn = $('wallet-btn');
const walletInput = $('wallet-input');
const walletName = $('wallet-name');
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

let walletContent = null;   // raw base64 text string
let walletRaw = null;       // decoded bytes (Uint8Array)
let running = false;
let stopRequested = false;

/* MessageChannel-based yield: allows a repaint between passwords. */
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
function setWalletName(text, state, title) {
    walletName.textContent = text;
    walletName.classList.remove('set', 'valid', 'invalid');
    if (state) walletName.classList.add(state);
    if (title) walletName.title = title; else walletName.removeAttribute('title');
}

walletBtn.addEventListener('click', () => walletInput.click());

walletInput.addEventListener('change', async () => {
    const file = walletInput.files[0];
    if (!file) return;
    walletContent = null;
    walletRaw = null;
    try {
        const text = (await file.text()).trim();
        const label = `${file.name} (${file.size} byte)`;
        let info;
        try {
            info = checkMagic(text);
        } catch (e) {
            setWalletName(label, 'invalid', 'Could not base64-decode — does not appear to be an Electrum wallet.');
            return;
        }
        if (info.magic === 'BIE1') {
            walletContent = text;
            walletRaw = info.raw;
            setWalletName(label, 'valid', 'Valid password-encrypted Electrum wallet (BIE1)');
        } else if (info.magic === 'BIE2') {
            setWalletName(label, 'invalid', 'BIE2-encrypted (hardware wallet/xpub password) — not supported.');
        } else {
            setWalletName(label, 'invalid', 'No BIE1 magic — the file does not appear to be password-encrypted.');
        }
    } catch (e) {
        setWalletName('Could not read the file', null);
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
        pwName.textContent = 'Could not read the file';
        pwName.classList.remove('set');
    }
});

/* ---------- run ---------- */
function setRunning(state) {
    running = state;
    runBtn.classList.toggle('display-none', state);
    stopBtn.classList.toggle('display-none', !state);
    walletBtn.disabled = state;
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
});

async function run() {
    if (running) return;

    if (!walletContent || !walletRaw) { showToast('Choose a valid BIE1 wallet file first'); return; }
    const passwords = parsePasswords();
    if (passwords.length === 0) { showToast('Add at least one password'); return; }

    if (typeof DecompressionStream === 'undefined') {
        clearOutput();
        log('Your browser lacks DecompressionStream support — cannot continue.', 'log-err');
        return;
    }

    stopRequested = false;
    setRunning(true);
    resultPanel.classList.add('display-none');
    progressWrap.classList.remove('display-none');
    progressBar.style.width = '0%';
    clearOutput();
    log('Format: BIE1-ECIES (secp256k1 + AES-128-CBC) → zlib → JSON', 'log-muted');
    log(`Testing ${passwords.length} passwords…`, 'log-muted');

    const total = passwords.length;
    const t0 = performance.now();
    let found = null;

    for (let i = 0; i < total; i++) {
        if (stopRequested) {
            log(`\nStopped by the user at ${i} of ${total}.`, 'log-err');
            break;
        }

        const pw = passwords[i];
        progressStatus.textContent = `[${i + 1}/${total}] testing: ${pw}`;
        progressBar.style.width = ((i / total) * 100).toFixed(1) + '%';
        await yieldToUI();

        try {
            const jsonText = await decryptWalletFile(walletRaw, pw);
            if (jsonText !== null) { found = { password: pw, jsonText, index: i + 1 }; break; }
        } catch (e) {
            log(`  [${i + 1}] "${pw}" → unexpected error: ${e.message}`, 'log-err');
        }
    }

    progressBar.style.width = '100%';
    const secs = ((performance.now() - t0) / 1000).toFixed(1);

    if (found) {
        progressStatus.textContent = `Done — password found on attempt ${found.index} of ${total} (${secs}s)`;
        await presentResult(found.password, found.jsonText, found.index);
    } else if (stopRequested) {
        progressStatus.textContent = `Stopped (${secs}s)`;
    } else {
        progressStatus.textContent = `Done — no matching password (${secs}s)`;
        log(`\n✗ None of the ${total} passwords matched.`, 'log-err');
        showResult(false, '✗ No matching password', [
            { label: 'Result', value: `Tested ${total} passwords with no match. Check the list or add more.`, copy: false },
        ]);
    }

    setRunning(false);
}

async function presentResult(password, jsonText, index) {
    log(`\n✓ MATCH on password #${index}: ${password}`, 'log-hit');

    let data;
    try {
        data = JSON.parse(jsonText);
    } catch (e) {
        // Decrypted but not valid JSON — show the raw text anyway
        showResult(true, '✓ Wallet unlocked', [{ label: 'Password', value: password }]);
        log('\nDecrypted content (not JSON):', 'log-ok');
        log(jsonText);
        return;
    }

    const walletType = data.wallet_type || 'unknown';
    const seedVersion = data.seed_version != null ? data.seed_version : 'unknown';
    log(`wallet_type:  ${walletType}`, 'log-ok');
    log(`seed_version: ${seedVersion}`, 'log-ok');

    const fields = [{ label: 'Password', value: password }];
    const keystores = collectKeystores(data);
    let seedFound = false;

    for (const [name, ks] of keystores) {
        if (!ks.seed) {
            log(`${name}: no seed phrase (imported keys or hardware wallet)`, 'log-muted');
            continue;
        }
        let seed;
        try { seed = await pwDecode(ks.seed, password); }
        catch (e) { seed = ks.seed; }
        const label = keystores.length > 1 ? `Seed phrase (${name})` : 'Seed phrase (mnemonic)';
        fields.push({ label, value: seed });
        seedFound = true;
        log(`\nMnemonic (${name}): ${seed}`, 'log-ok');

        if (ks.passphrase) {
            let pp;
            try { pp = await pwDecode(ks.passphrase, password); }
            catch (e) { pp = ks.passphrase; }
            fields.push({ label: `Passphrase (${name})`, value: pp });
            log(`Passphrase (${name}): ${pp}`, 'log-ok');
        }
    }

    if (!seedFound) {
        fields.push({ label: 'Info', value: 'No encrypted seed phrase in the wallet (e.g. watching-only or imported keys).', copy: false });
    }

    fields.push({ label: `wallet_type / seed_version`, value: `${walletType} / ${seedVersion}`, copy: false });

    showResult(true, '✓ Wallet unlocked!', fields);

    // Full decrypted JSON in the log (selectable/copyable text)
    log('\n— Full decrypted wallet JSON —', 'log-muted');
    log(JSON.stringify(data, null, 2));
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
