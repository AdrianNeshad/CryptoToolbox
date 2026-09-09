/* =========================================================================
   MetaMask Vault Decryptor — dictionary variant.

   The decryption core is ported byte-by-byte from
   @metamask/browser-passworder (the same package that MetaMask's official
   vault decryptor uses):
     PBKDF2-SHA256  → key stretching (iterations from the vault's keyMetadata,
                      10,000 for older vaults without keyMetadata)
     AES-256-GCM    → decryption (auth-tag error = wrong password)
   The vault extraction (paste / file / Chrome log format) is ported from
   vault-decryptor/app/lib.js. Everything runs locally via WebCrypto.
   ========================================================================= */

/* ---------- base64 → bytes ---------- */

function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/* ---------- key derivation + decryption (browser-passworder port) ---------- */

async function deriveKey(password, saltB64, iterations) {
    const pwBytes = new TextEncoder().encode(password);
    const saltBytes = b64ToBytes(saltB64);
    const baseKey = await crypto.subtle.importKey('raw', pwBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
}

function vaultIterations(vault) {
    // browser-passworder: keyMetadata.params.iterations, otherwise OLD_DERIVATION_PARAMS (10000)
    return (vault.keyMetadata && vault.keyMetadata.params && vault.keyMetadata.params.iterations) || 10000;
}

/* Throws OperationError on a wrong password (GCM auth fails). */
async function decryptVaultOnce(password, vault, key) {
    const cryptoKey = key || (await deriveKey(password, vault.salt, vaultIterations(vault)));
    const iv = b64ToBytes(vault.iv);
    const data = b64ToBytes(vault.data);
    const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
    const str = new TextDecoder().decode(new Uint8Array(ptBuf));
    return JSON.parse(str); // array of keyrings
}

function decodeMnemonic(mnemonic) {
    if (typeof mnemonic === 'string') return mnemonic;
    // modern MetaMask: array of UTF-8 byte codes
    try { return new TextDecoder().decode(new Uint8Array(mnemonic)); }
    catch (e) { return String(mnemonic); }
}

function collectMnemonics(keyrings) {
    const out = [];
    (keyrings || []).forEach(k => {
        if (k && k.data && Object.prototype.hasOwnProperty.call(k.data, 'mnemonic')) {
            out.push(decodeMnemonic(k.data.mnemonic));
        }
    });
    return out;
}

/* ---------- vault extraction (port of app/lib.js) ---------- */

function dedupe(arr) {
    const result = [];
    (arr || []).forEach(x => {
        if (x == null) return;
        if (!result.find(y => Object.keys(x).length === Object.keys(y).length &&
            Object.entries(x).every(([k, ex]) => y[k] === ex))) {
            result.push(x);
        }
    });
    return result;
}

function isVaultValid(vault) {
    return typeof vault === 'object' && vault !== null &&
        ['data', 'iv', 'salt'].every(e => typeof vault[e] === 'string');
}

function extractVaultFromFile(data) {
    let vaultBody;
    try { return JSON.parse(data); } catch (err) { /* not pure JSON */ }
    {
        // pre-v3 plaintext
        const matches = data.match(/{"wallet-seed":"([^"}]*)"/);
        if (matches && matches.length) {
            const mnemonic = matches[1].replace(/\\n*/, '');
            const vaultMatches = data.match(/"wallet":("{[ -~]*\\"version\\":2}")/);
            const vault = vaultMatches ? JSON.parse(JSON.parse(vaultMatches[1])) : {};
            return { data: Object.assign({}, { mnemonic }, vault) };
        }
    }
    {
        // chromium 000003.log (linux)
        const matches = data.match(/"KeyringController":{"vault":"{[^{}]*}"/);
        if (matches && matches.length) {
            vaultBody = matches[0].substring(29);
            return JSON.parse(JSON.parse(vaultBody));
        }
    }
    {
        // chromium 000006.log (macOS)
        const matches = data.match(/KeyringController":(\{"vault":".*?=\\"\}"\})/);
        if (matches && matches.length) {
            try {
                const frag = matches[1];
                const dataRegex = /\\"data\\":\\"([A-Za-z0-9+\/]*=*)/u;
                const ivRegex = /,\\"iv\\":\\"([A-Za-z0-9+\/]{10,40}=*)/u;
                const saltRegex = /,\\"salt\\":\\"([A-Za-z0-9+\/]{10,100}=*)\\"/;
                const keyMetaRegex = /,\\"keyMetadata\\":(.*}})/;
                const parts = [dataRegex, ivRegex, saltRegex, keyMetaRegex]
                    .map(r => frag.match(r)).map(m => m[1]);
                return { data: parts[0], iv: parts[1], salt: parts[2], keyMetadata: JSON.parse(parts[3].replaceAll('\\', '')) };
            } catch (err) { /* continue */ }
        }
    }
    {
        // chromium 0000056.log (macOS, with keyringsMetadata)
        const matches = data.match(/"KeyringController":(\{.*?"vault":".*?=\\"\}"\})/);
        if (matches && matches.length) {
            try {
                const frag = matches[1];
                const dataRegex = /\\"data\\":\\"([A-Za-z0-9+\/]*=*)/u;
                const ivRegex = /,\\"iv\\":\\"([A-Za-z0-9+\/]{10,40}=*)/u;
                const saltRegex = /,\\"salt\\":\\"([A-Za-z0-9+\/]{10,100}=*)\\"/;
                const keyMetaRegex = /,\\"keyMetadata\\":(.*}})/;
                const parts = [dataRegex, ivRegex, saltRegex, keyMetaRegex]
                    .map(r => frag.match(r)).map(m => m[1]);
                return { data: parts[0], iv: parts[1], salt: parts[2], keyMetadata: JSON.parse(parts[3].replaceAll('\\', '')) };
            } catch (err) { /* continue */ }
        }
    }
    {
        // chromium 000005.ldb (windows)
        const matchRegex = /Keyring[0-9][^\}]*(\{[^\{\}]*\\"\})/gu;
        const captureRegex = /Keyring[0-9][^\}]*(\{[^\{\}]*\\"\})/u;
        const ivRegex = /\\"iv.{1,4}[^A-Za-z0-9+\/]{1,10}([A-Za-z0-9+\/]{10,40}=*)/u;
        const dataRegex = /\\"[^":,is]*\\":\\"([A-Za-z0-9+\/]*=*)/u;
        const saltRegex = /,\\"salt.{1,4}[^A-Za-z0-9+\/]{1,10}([A-Za-z0-9+\/]{10,100}=*)/u;
        const vaults = dedupe(data.match(matchRegex)?.map(m => m.match(captureRegex)[1])
            .map(s => [dataRegex, ivRegex, saltRegex].map(r => s.match(r)))
            .filter(([d, i, s]) => d && d.length > 1 && i && i.length > 1 && s && s.length > 1)
            .map(([d, i, s]) => ({ data: d[1], iv: i[1], salt: s[1] })));
        if (vaults.length) return vaults[0];
    }
    {
        // split state format, chromium 000004.log (windows-2)
        const vaultRegex = /KeyringController[\s\S]*?"vault":"((?:[^"\\]|\\.)*)"/g;
        const vaults = [];
        let match;
        while ((match = vaultRegex.exec(data)) !== null) {
            try {
                const vaultString = JSON.parse(`"${match[1]}"`);
                vaults.push(JSON.parse(vaultString));
            } catch (err) { /* continue */ }
        }
        const deduped = dedupe(vaults);
        if (deduped.length) return deduped[0];
    }
    return null;
}

/* Parses the text box: pure JSON or a pasted log format. */
function parseVaultText(text) {
    const trimmed = text.trim();
    if (!trimmed) return null;
    try {
        const v = JSON.parse(trimmed);
        if (isVaultValid(v) || (v && v.data && v.data.mnemonic)) return v;
    } catch (e) { /* try extraction below */ }
    const v2 = extractVaultFromFile(trimmed);
    if (v2 && (isVaultValid(v2) || (v2.data && v2.data.mnemonic))) return v2;
    return null;
}

/* =========================================================================
   UI  (harness mirrored from secoUnlock)
   ========================================================================= */

const $ = id => document.getElementById(id);

const vaultBtn = $('vault-btn');
const vaultInput = $('vault-input');
const vaultName = $('vault-name');
const vaultText = $('vault-text');
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

let running = false;
let stopRequested = false;

/* MessageChannel-based yield (like secoUnlock) */
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
    return pwList.value.split('\n').map(p => p.replace(/\r$/, '')).filter(p => p.length > 0);
}

function updatePwCount() {
    const n = parsePasswords().length;
    pwCount.textContent = n > 0 ? `${n} passwords` : '';
}

pwList.addEventListener('input', updatePwCount);

/* ---------- vault-status ---------- */

function setVaultName(text, state, title) {
    vaultName.textContent = text;
    vaultName.classList.remove('set', 'valid', 'invalid');
    if (state) vaultName.classList.add(state);
    if (title) vaultName.title = title; else vaultName.removeAttribute('title');
}

function refreshVaultState() {
    const text = vaultText.value.trim();
    if (!text) { setVaultName('No vault loaded', null); return null; }
    const vault = parseVaultText(text);
    if (vault && vault.data && vault.data.mnemonic) {
        setVaultName('Unencrypted vault (seed in plaintext)', 'valid', 'The vault is already decrypted');
    } else if (vault) {
        setVaultName(`Valid vault — PBKDF2 ${vaultIterations(vault).toLocaleString('en-US')} iterations`, 'valid');
    } else {
        setVaultName('Invalid vault data', 'invalid', 'Could not find {data, iv, salt}');
    }
    return vault;
}

vaultText.addEventListener('input', refreshVaultState);

vaultBtn.addEventListener('click', () => vaultInput.click());

vaultInput.addEventListener('change', async () => {
    const file = vaultInput.files[0];
    if (!file) return;
    try {
        const text = await file.text();
        const vault = extractVaultFromFile(text);
        if (vault && (isVaultValid(vault) || (vault.data && vault.data.mnemonic))) {
            vaultText.value = JSON.stringify(vault);
        } else {
            vaultText.value = text;
        }
        refreshVaultState();
    } catch (e) {
        setVaultName('Could not read the file', 'invalid');
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
    vaultBtn.disabled = state;
    pwBtn.disabled = state;
    pwList.disabled = state;
    vaultText.disabled = state;
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

function mnemonicFields(mnemonics, extra) {
    const fields = (extra || []);
    if (mnemonics.length === 1) {
        fields.push({ label: 'Seed phrase (mnemonic)', value: mnemonics[0] });
    } else if (mnemonics.length > 1) {
        mnemonics.forEach((m, i) => fields.push({ label: `Seed phrase #${i + 1}`, value: m }));
    }
    return fields;
}

runBtn.addEventListener('click', run);
stopBtn.addEventListener('click', () => {
    stopRequested = true;
    progressStatus.textContent = 'Stopping…';
});

async function run() {
    if (running) return;

    const vault = refreshVaultState();
    if (!vault) { showToast('Paste or load valid vault data first'); return; }

    resultPanel.classList.add('display-none');

    // Already decrypted vault (plaintext)
    if (vault.data && vault.data.mnemonic) {
        clearOutput();
        const mnemonic = decodeMnemonic(vault.data.mnemonic);
        log('The vault was already unencrypted — no password was needed.', 'log-ok');
        log(`Mnemonic: ${mnemonic}`, 'log-hit');
        showResult(true, '✓ Seed phrase extracted (unencrypted vault)',
            mnemonicFields([mnemonic]));
        return;
    }

    const passwords = parsePasswords();
    if (passwords.length === 0) { showToast('Add at least one password'); return; }

    stopRequested = false;
    setRunning(true);
    progressWrap.classList.remove('display-none');
    progressBar.style.width = '0%';
    clearOutput();

    const iterations = vaultIterations(vault);
    log(`PBKDF2-SHA256 with ${iterations.toLocaleString('en-US')} iterations per attempt.`, 'log-muted');
    if (iterations >= 100000) {
        log('NOTE: MetaMask\'s key stretching is deliberately heavy — each password takes a while.', 'log-muted');
    }
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
            const keyrings = await decryptVaultOnce(pw, vault);
            const mnemonics = collectMnemonics(keyrings);
            found = { password: pw, mnemonics, keyrings, index: i + 1 };
            break;
        } catch (e) {
            // OperationError = wrong password; anything else = unexpected error
            if (e && e.name !== 'OperationError') {
                log(`  [${i + 1}] "${pw}" → unexpected error: ${e.message}`, 'log-err');
            }
        }
    }

    progressBar.style.width = '100%';
    const secs = ((performance.now() - t0) / 1000).toFixed(1);

    if (found) {
        progressStatus.textContent = `Done — password found on attempt ${found.index} of ${total} (${secs}s)`;
        log(`\n✓ MATCH on password #${found.index}: ${found.password}`, 'log-hit');
        if (found.mnemonics.length) {
            found.mnemonics.forEach(m => log(`Mnemonic: ${m}`, 'log-ok'));
        } else {
            log('The vault was decrypted but contained no HD mnemonic (e.g. only imported keys).', 'log-ok');
        }
        const extra = [{ label: 'Password', value: found.password }];
        let fields;
        if (found.mnemonics.length) {
            fields = mnemonicFields(found.mnemonics, extra);
        } else {
            extra.push({ label: 'Decrypted vault (raw)', value: JSON.stringify(found.keyrings, null, 2) });
            fields = extra;
        }
        showResult(true, '✓ Password found!', fields);
    } else if (stopRequested) {
        progressStatus.textContent = `Stopped (${secs}s)`;
    } else {
        progressStatus.textContent = `Done — no matching password (${secs}s)`;
        log(`\n✗ None of the ${total} passwords matched.`, 'log-err');
        showResult(false, '✗ No matching password', [
            { label: 'Result', value: `Tested ${total} passwords with no match. Check the vault data or add more passwords.`, copy: false },
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
