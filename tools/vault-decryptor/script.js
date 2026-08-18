/* =========================================================================
   MetaMask Vault Decryptor — dictionary-variant.

   Dekrypteringskärnan är porterad byte-för-byte från
   @metamask/browser-passworder (samma paket som MetaMasks officiella
   vault-decryptor använder):
     PBKDF2-SHA256  → nyckelsträckning (iterationer från vaultens keyMetadata,
                      10 000 för äldre vaults utan keyMetadata)
     AES-256-GCM    → dekryptering (auth-tag-fel = fel lösenord)
   Vault-extraheringen (paste / fil / Chrome-loggformat) är porterad från
   vault-decryptor/app/lib.js. Allt körs lokalt via WebCrypto.
   ========================================================================= */

/* ---------- base64 → bytes ---------- */

function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/* ---------- nyckelhärledning + dekryptering (browser-passworder-port) ---------- */

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
    // browser-passworder: keyMetadata.params.iterations, annars OLD_DERIVATION_PARAMS (10000)
    return (vault.keyMetadata && vault.keyMetadata.params && vault.keyMetadata.params.iterations) || 10000;
}

/* Kastar OperationError vid fel lösenord (GCM-auth misslyckas). */
async function decryptVaultOnce(password, vault, key) {
    const cryptoKey = key || (await deriveKey(password, vault.salt, vaultIterations(vault)));
    const iv = b64ToBytes(vault.iv);
    const data = b64ToBytes(vault.data);
    const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
    const str = new TextDecoder().decode(new Uint8Array(ptBuf));
    return JSON.parse(str); // array av keyrings
}

function decodeMnemonic(mnemonic) {
    if (typeof mnemonic === 'string') return mnemonic;
    // modern MetaMask: array av UTF-8 byte-koder
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

/* ---------- vault-extrahering (port av app/lib.js) ---------- */

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
    try { return JSON.parse(data); } catch (err) { /* inte ren JSON */ }
    {
        // pre-v3 klartext
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
            } catch (err) { /* fortsätt */ }
        }
    }
    {
        // chromium 0000056.log (macOS, med keyringsMetadata)
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
            } catch (err) { /* fortsätt */ }
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
        // split state-format, chromium 000004.log (windows-2)
        const vaultRegex = /KeyringController[\s\S]*?"vault":"((?:[^"\\]|\\.)*)"/g;
        const vaults = [];
        let match;
        while ((match = vaultRegex.exec(data)) !== null) {
            try {
                const vaultString = JSON.parse(`"${match[1]}"`);
                vaults.push(JSON.parse(vaultString));
            } catch (err) { /* fortsätt */ }
        }
        const deduped = dedupe(vaults);
        if (deduped.length) return deduped[0];
    }
    return null;
}

/* Tolkar textrutan: ren JSON eller ett inklistrat loggformat. */
function parseVaultText(text) {
    const trimmed = text.trim();
    if (!trimmed) return null;
    try {
        const v = JSON.parse(trimmed);
        if (isVaultValid(v) || (v && v.data && v.data.mnemonic)) return v;
    } catch (e) { /* prova extrahering nedan */ }
    const v2 = extractVaultFromFile(trimmed);
    if (v2 && (isVaultValid(v2) || (v2.data && v2.data.mnemonic))) return v2;
    return null;
}

/* =========================================================================
   UI  (harness speglat från secoUnlock)
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

let running = false;
let stopRequested = false;

/* MessageChannel-baserad yield (som secoUnlock) */
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
    return pwList.value.split('\n').map(p => p.replace(/\r$/, '')).filter(p => p.length > 0);
}

function updatePwCount() {
    const n = parsePasswords().length;
    pwCount.textContent = n > 0 ? `${n} lösenord` : '';
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
    if (!text) { setVaultName('Ingen vault inläst', null); return null; }
    const vault = parseVaultText(text);
    if (vault && vault.data && vault.data.mnemonic) {
        setVaultName('Okrypterad vault (seed i klartext)', 'valid', 'Vaulten är redan dekrypterad');
    } else if (vault) {
        setVaultName(`Giltig vault — PBKDF2 ${vaultIterations(vault).toLocaleString('sv-SE')} iterationer`, 'valid');
    } else {
        setVaultName('Ogiltig vault-data', 'invalid', 'Kunde inte hitta {data, iv, salt}');
    }
    return vault;
}

vaultText.addEventListener('input', refreshVaultState);

function applyVaultText(text) {
    const vault = extractVaultFromFile(text);
    if (vault && (isVaultValid(vault) || (vault.data && vault.data.mnemonic))) {
        vaultText.value = JSON.stringify(vault);
    } else {
        vaultText.value = text;
    }
    refreshVaultState();
}

function applyPasswordText(text, label) {
    pwList.value = text;
    pwName.textContent = label;
    pwName.classList.add('set');
    updatePwCount();
}

vaultBtn.addEventListener('click', () => vaultInput.click());

vaultInput.addEventListener('change', async () => {
    const file = vaultInput.files[0];
    if (!file) return;
    try {
        applyVaultText(await file.text());
    } catch (e) {
        setVaultName('Kunde inte läsa filen', 'invalid');
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
        const [vaultRes, pwRes] = await Promise.all([
            fetch('test/vault.json'),
            fetch('test/passwords.txt'),
        ]);
        if (!vaultRes.ok || !pwRes.ok) throw new Error('Testfilerna kunde inte hämtas.');
        applyVaultText(await vaultRes.text());
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
    vaultBtn.disabled = state;
    pwBtn.disabled = state;
    pwList.disabled = state;
    vaultText.disabled = state;
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

function mnemonicFields(mnemonics, extra) {
    const fields = (extra || []);
    if (mnemonics.length === 1) {
        fields.push({ label: 'Seed-fras (mnemonic)', value: mnemonics[0] });
    } else if (mnemonics.length > 1) {
        mnemonics.forEach((m, i) => fields.push({ label: `Seed-fras #${i + 1}`, value: m }));
    }
    return fields;
}

runBtn.addEventListener('click', run);
stopBtn.addEventListener('click', () => {
    stopRequested = true;
    progressStatus.textContent = 'Stoppar…';
});

async function run() {
    if (running) return;

    const vault = refreshVaultState();
    if (!vault) { showToast('Klistra in eller ladda giltig vault-data först'); return; }

    resultPanel.classList.add('display-none');

    // Redan dekrypterad vault (klartext)
    if (vault.data && vault.data.mnemonic) {
        clearOutput();
        const mnemonic = decodeMnemonic(vault.data.mnemonic);
        log('Vaulten var redan okrypterad — inget lösenord behövdes.', 'log-ok');
        log(`Mnemonic: ${mnemonic}`, 'log-hit');
        showResult(true, '✓ Seed-fras extraherad (okrypterad vault)',
            mnemonicFields([mnemonic]));
        return;
    }

    const passwords = parsePasswords();
    if (passwords.length === 0) { showToast('Lägg till minst ett lösenord'); return; }

    stopRequested = false;
    setRunning(true);
    progressWrap.classList.remove('display-none');
    progressBar.style.width = '0%';
    clearOutput();

    const iterations = vaultIterations(vault);
    log(`PBKDF2-SHA256 med ${iterations.toLocaleString('sv-SE')} iterationer per försök.`, 'log-muted');
    if (iterations >= 100000) {
        log('OBS: MetaMasks nyckelsträckning är avsiktligt tung — varje lösenord tar en stund.', 'log-muted');
    }
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
            const keyrings = await decryptVaultOnce(pw, vault);
            const mnemonics = collectMnemonics(keyrings);
            found = { password: pw, mnemonics, keyrings, index: i + 1 };
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
        if (found.mnemonics.length) {
            found.mnemonics.forEach(m => log(`Mnemonic: ${m}`, 'log-ok'));
        } else {
            log('Vaulten dekrypterades men innehöll ingen HD-mnemonic (t.ex. bara importerade nycklar).', 'log-ok');
        }
        const extra = [{ label: 'Lösenord', value: found.password }];
        let fields;
        if (found.mnemonics.length) {
            fields = mnemonicFields(found.mnemonics, extra);
        } else {
            extra.push({ label: 'Dekrypterad vault (rå)', value: JSON.stringify(found.keyrings, null, 2) });
            fields = extra;
        }
        showResult(true, '✓ Lösenord hittat!', fields);
    } else if (stopRequested) {
        progressStatus.textContent = `Stoppad (${secs}s)`;
    } else {
        progressStatus.textContent = `Klar — inget matchande lösenord (${secs}s)`;
        log(`\n✗ Inget av de ${total} lösenorden matchade.`, 'log-err');
        showResult(false, '✗ Inget matchande lösenord', [
            { label: 'Resultat', value: `Testade ${total} lösenord utan träff. Kontrollera vault-datan eller lägg till fler lösenord.`, copy: false },
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
