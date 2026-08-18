/* =========================================================================
   Electrum wallet decrypt-kärna — porterad från electrumUnlock/main.py.
   Kör helt lokalt via WebCrypto (crypto.subtle), BigInt (secp256k1) och
   DecompressionStream. Ingen BIP39-ordlista behövs: Electrum lagrar
   seed-frasen som (krypterad) text, inte som entropi.

   Lager:
     1. Yttre: BIE1-ECIES (secp256k1 + AES-128-CBC + HMAC-SHA256) → zlib → JSON
     2. Inre:  keystore['seed']/['passphrase'] = base64(iv + AES-256-CBC),
               nyckel = SHA256(SHA256(lösenord))
   ========================================================================= */

/* ---------- hjälpare ---------- */
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

/* ---------- WebCrypto-primitiver ---------- */
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

/* ---------- Electrum-logik ---------- */
async function getEckeyFromPassword(password) {
    const secret = await pbkdf2Sha512(utf8(password), new Uint8Array(0), 1024, 64);
    return mod(bytesToBigIntBE(secret), N);
}

// Returnerar plaintext (Uint8Array) eller null vid MAC-fel (fel lösenord).
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

// Returnerar JSON-text vid rätt lösenord, null vid fel lösenord. Kastar vid formatfel.
async function decryptWalletFile(raw, password) {
    const d = await getEckeyFromPassword(password);
    const plaintext = await eciesDecrypt(d, raw);
    if (plaintext === null) return null; // fel lösenord (MAC-fel)
    const jsonBytes = await inflate(plaintext);
    return new TextDecoder().decode(jsonBytes);
}

// Inre fält-kryptering (seed/passphrase): key = SHA256(SHA256(pw)), base64(iv[16] + AES-256-CBC).
async function pwDecode(encodedStr, password) {
    const secret = await sha256(await sha256(utf8(password)));
    const raw = b64decode(encodedStr);
    if (raw.length < 32) throw new Error('för kort');
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

let walletContent = null;   // rå base64-textsträng
let walletRaw = null;       // avkodade byte (Uint8Array)
let running = false;
let stopRequested = false;

/* MessageChannel-baserad yield: släpper fram en repaint mellan lösenord. */
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

function clearOutput() { output.textContent = ''; }

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
            setWalletName(label, 'invalid', 'Kunde inte base64-avkoda — verkar inte vara en Electrum-wallet.');
            return;
        }
        if (info.magic === 'BIE1') {
            walletContent = text;
            walletRaw = info.raw;
            setWalletName(label, 'valid', 'Giltig lösenordskrypterad Electrum-wallet (BIE1)');
        } else if (info.magic === 'BIE2') {
            setWalletName(label, 'invalid', 'BIE2-krypterad (hårdvaruplånbok/xpub-lösenord) — stöds inte.');
        } else {
            setWalletName(label, 'invalid', 'Ingen BIE1-magic — filen verkar inte vara lösenordskrypterad.');
        }
    } catch (e) {
        setWalletName('Kunde inte läsa filen', null);
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

    if (!walletContent || !walletRaw) { showToast('Välj en giltig BIE1-wallet-fil först'); return; }
    const passwords = parsePasswords();
    if (passwords.length === 0) { showToast('Lägg till minst ett lösenord'); return; }

    if (typeof DecompressionStream === 'undefined') {
        clearOutput();
        log('Din webbläsare saknar stöd för DecompressionStream — kan inte fortsätta.', 'log-err');
        return;
    }

    stopRequested = false;
    setRunning(true);
    resultPanel.classList.add('display-none');
    progressWrap.classList.remove('display-none');
    progressBar.style.width = '0%';
    clearOutput();
    log('Format: BIE1-ECIES (secp256k1 + AES-128-CBC) → zlib → JSON', 'log-muted');
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
            const jsonText = await decryptWalletFile(walletRaw, pw);
            if (jsonText !== null) { found = { password: pw, jsonText, index: i + 1 }; break; }
        } catch (e) {
            log(`  [${i + 1}] "${pw}" → oväntat fel: ${e.message}`, 'log-err');
        }
    }

    progressBar.style.width = '100%';
    const secs = ((performance.now() - t0) / 1000).toFixed(1);

    if (found) {
        progressStatus.textContent = `Klar — lösenord hittat på försök ${found.index} av ${total} (${secs}s)`;
        await presentResult(found.password, found.jsonText, found.index);
    } else if (stopRequested) {
        progressStatus.textContent = `Stoppad (${secs}s)`;
    } else {
        progressStatus.textContent = `Klar — inget matchande lösenord (${secs}s)`;
        log(`\n✗ Inget av de ${total} lösenorden matchade.`, 'log-err');
        showResult(false, '✗ Inget matchande lösenord', [
            { label: 'Resultat', value: `Testade ${total} lösenord utan träff. Kontrollera listan eller lägg till fler.`, copy: false },
        ]);
    }

    setRunning(false);
}

async function presentResult(password, jsonText, index) {
    log(`\n✓ MATCH på lösenord #${index}: ${password}`, 'log-hit');

    let data;
    try {
        data = JSON.parse(jsonText);
    } catch (e) {
        // Dekrypterat men inte giltig JSON — visa ändå råtexten
        showResult(true, '✓ Plånbok upplåst', [{ label: 'Lösenord', value: password }]);
        log('\nDekrypterat innehåll (ej JSON):', 'log-ok');
        log(jsonText);
        return;
    }

    const walletType = data.wallet_type || 'okänd';
    const seedVersion = data.seed_version != null ? data.seed_version : 'okänd';
    log(`wallet_type:  ${walletType}`, 'log-ok');
    log(`seed_version: ${seedVersion}`, 'log-ok');

    const fields = [{ label: 'Lösenord', value: password }];
    const keystores = collectKeystores(data);
    let seedFound = false;

    for (const [name, ks] of keystores) {
        if (!ks.seed) {
            log(`${name}: ingen seed-fras (importerade nycklar eller hårdvaruplånbok)`, 'log-muted');
            continue;
        }
        let seed;
        try { seed = await pwDecode(ks.seed, password); }
        catch (e) { seed = ks.seed; }
        const label = keystores.length > 1 ? `Seed-fras (${name})` : 'Seed-fras (mnemonic)';
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
        fields.push({ label: 'Info', value: 'Ingen krypterad seed-fras i plånboken (t.ex. watching-only eller importerade nycklar).', copy: false });
    }

    fields.push({ label: `wallet_type / seed_version`, value: `${walletType} / ${seedVersion}`, copy: false });

    showResult(true, '✓ Plånbok upplåst!', fields);

    // Fullständig dekrypterad JSON i loggen (markerbar/kopierbar text)
    log('\n— Fullständig dekrypterad plånboks-JSON —', 'log-muted');
    log(JSON.stringify(data, null, 2));
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
