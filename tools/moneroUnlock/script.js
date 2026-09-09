/* =========================================================================
   Monero .keys — wallet recovery + dictionary attack (UI logic)
   -------------------------------------------------------------------------
   Tests one or more passwords against a .keys file. Each attempt requires a
   CryptoNight hash (~0.5–1 s), so the loop yields a repaint between each
   password (so that Stop and the progress work). The correct password is recognized
   by the outer layer decrypting to valid JSON; only then is the second
   (heavier) derivation run to unmask the secret keys.
   ========================================================================= */
(function () {
    "use strict";

    var MK = window.MoneroKeys;
    var WORDS = window.MONERO_WORDS_EN;
    var $ = function (id) { return document.getElementById(id); };

    var keysBtn = $('keys-btn');
    var keysInput = $('keys-input');
    var keysName = $('keys-name');
    var pwBtn = $('pw-btn');
    var pwInput = $('pw-input');
    var pwName = $('pw-name');
    var pwCount = $('pw-count');
    var pwList = $('pw-list');
    var kdfInput = $('kdf-rounds');
    var netSelect = $('net');
    var runBtn = $('run-btn');
    var stopBtn = $('stop-btn');
    var clearBtn = $('clear-btn');
    var output = $('output');
    var resultPanel = $('result-panel');
    var progressWrap = $('progress-wrap');
    var progressBar = $('progress-bar');
    var progressStatus = $('progress-status');
    var toast = $('toast');

    var fileBytes = null;
    var running = false;
    var stopRequested = false;
    var toastTimer = null;

    /* ---------- helpers ---------- */
    function hexToBytes(h) { var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
    function cnHash(u8) { return hexToBytes(window.cn_slow_hash(u8)); }
    function utf8Bytes(str) {
        if (window.TextEncoder) return new TextEncoder().encode(str);
        var out = [], i, c;
        for (i = 0; i < str.length; i++) {
            c = str.charCodeAt(i);
            if (c < 0x80) out.push(c);
            else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
            else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
        }
        return new Uint8Array(out);
    }

    // MessageChannel yield: allows a repaint without the setTimeout(0) clamp.
    var _mc = new MessageChannel();
    var _yieldResolve = null;
    _mc.port1.onmessage = function () { if (_yieldResolve) { var r = _yieldResolve; _yieldResolve = null; r(); } };
    function yieldToUI() { return new Promise(function (resolve) { _yieldResolve = resolve; _mc.port2.postMessage(0); }); }

    function log(text, cls) {
        var span = document.createElement('span');
        if (cls) span.className = cls;
        span.textContent = text + '\n';
        output.appendChild(span);
        output.scrollTop = output.scrollHeight;
    }
    function clearOutput() { output.textContent = ''; }

    function showToast(text) {
        toast.textContent = text; toast.classList.add('show');
        if (toastTimer) clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { toast.classList.remove('show'); }, 1800);
    }

    function copyText(text) {
        function done() { showToast('Copied'); }
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text); done(); });
                return;
            }
        } catch (e) { /* falls through */ }
        legacyCopy(text); done();
    }
    function legacyCopy(text) {
        var ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); } catch (e) { }
        document.body.removeChild(ta);
    }
    function esc(s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function fmtTime(sec) {
        sec = Math.round(sec);
        if (sec < 60) return sec + ' s';
        var m = Math.floor(sec / 60), s = sec % 60;
        if (m < 60) return m + ' min ' + s + ' s';
        var h = Math.floor(m / 60); m = m % 60;
        return h + ' h ' + m + ' min';
    }

    /* ---------- password list ---------- */
    function parsePasswords() {
        // NOTE: do not trim whitespace — passwords may contain it. Remove
        // line endings and only skip completely empty lines (except a single empty line,
        // which means "password-less wallet").
        var lines = pwList.value.split('\n').map(function (l) { return l.replace(/\r$/, ''); });
        var nonEmpty = lines.filter(function (l) { return l.length > 0; });
        if (nonEmpty.length === 0 && pwList.value.length === 0) return ['']; // empty field → try empty password
        if (nonEmpty.length === 0) return ['']; // only empty lines → empty password
        return nonEmpty;
    }
    function updatePwCount() {
        var n = parsePasswords().length;
        var raw = pwList.value.split('\n').filter(function (l) { return l.replace(/\r$/, '').length > 0; }).length;
        pwCount.textContent = raw > 1 ? (raw + ' passwords') : '';
    }
    pwList.addEventListener('input', updatePwCount);

    /* ---------- file selection ---------- */
    function setKeysName(text, state, title) {
        keysName.textContent = text;
        keysName.classList.remove('set', 'valid', 'invalid');
        if (state) keysName.classList.add(state);
        if (title) keysName.title = title; else keysName.removeAttribute('title');
    }
    keysBtn.addEventListener('click', function () { keysInput.click(); });
    keysInput.addEventListener('change', function () {
        var file = keysInput.files && keysInput.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function () {
            fileBytes = new Uint8Array(reader.result);
            var label = file.name + ' (' + fileBytes.length + ' byte)';
            try {
                MK.inspectContainer(fileBytes);
                setKeysName(label, 'valid', 'Looks like a valid .keys container');
                output.textContent = 'File loaded. Enter password and click Run.';
            } catch (e) {
                setKeysName(label, 'invalid', 'Uncertain file structure: ' + e.message + '. You can still try.');
            }
        };
        reader.onerror = function () { fileBytes = null; setKeysName('Could not read the file', 'invalid'); };
        reader.readAsArrayBuffer(file);
    });

    pwBtn.addEventListener('click', function () { pwInput.click(); });
    pwInput.addEventListener('change', function () {
        var file = pwInput.files && pwInput.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function () {
            pwList.value = reader.result;
            pwName.textContent = file.name;
            pwName.classList.add('set');
            updatePwCount();
        };
        reader.onerror = function () { pwName.textContent = 'Could not read the file'; pwName.classList.remove('set'); };
        reader.readAsText(file);
    });

    /* ---------- result rendering (full wallet on match) ---------- */
    function field(label, value, opts) {
        opts = opts || {};
        var valHtml = opts.seed ? '<div class="seed-box">' + esc(value) + '</div>' : '<code>' + esc(value) + '</code>';
        var copyBtn = opts.copy === false ? '' : '<button type="button" class="secondary copy-btn" data-copy="' + esc(value) + '">Copy</button>';
        var valWrapClass = opts.seed ? 'result-value column' : 'result-value';
        return '<div class="result-field">' +
            '<div class="result-label">' + esc(label) + '</div>' +
            '<div class="' + valWrapClass + '">' + valHtml + copyBtn + '</div>' +
            '</div>';
    }

    function renderResult(r, password, index, total) {
        var html = '';
        html += '<div class="result-title">✓ Wallet recovered</div>';

        var tags = '';
        tags += '<span class="tag">' + esc(r.network) + '</span>';
        tags += '<span class="tag">' + esc(r.cipher) + '</span>';
        if (r.watchOnly) tags += '<span class="tag warn">Watch-only</span>';
        else if (r.deterministic) tags += '<span class="tag good">Deterministic</span>';
        else tags += '<span class="tag warn">Non-deterministic</span>';
        html += '<div class="result-field"><div class="result-value" style="display:block">' + tags + '</div></div>';

        var pwDisplay = password === '' ? '(empty password)' : password;
        var pwOpts = password === '' ? { copy: false } : {};
        if (index > 0 && total > 1) {
            html += field('Password (match #' + index + ' of ' + total + ')', pwDisplay, pwOpts);
        } else {
            html += field('Password', pwDisplay, pwOpts);
        }

        html += field('Primary address', r.address);

        if (r.mnemonic) {
            html += field('Mnemonic seed (25 words' + (r.seedLanguage ? ', ' + r.seedLanguage : '') + ')', r.mnemonic, { seed: true });
        } else if (r.watchOnly) {
            html += '<div class="info-box" style="margin:0 0 12px">This is a <strong>watch-only</strong> wallet — it contains no spend key, so there is no seed phrase to recover.</div>';
        } else {
            html += '<div class="info-box" style="margin:0 0 12px">The wallet is <strong>non-deterministic</strong> — a 25-word phrase would not recreate the same view key, so no seed is shown. Use the keys below to import the wallet.</div>';
        }

        if (r.spendSecretKey) html += field('Private spend key', r.spendSecretKey);
        html += field('Private view key', r.viewSecretKey);
        html += field('Public spend key', r.spendPublicKey);
        html += field('Public view key', r.viewPublicKey);

        if (r.creationTimestamp) {
            var d = new Date(r.creationTimestamp * 1000);
            var ds = isNaN(d.getTime()) ? String(r.creationTimestamp) : d.toISOString().slice(0, 10) + ' (' + r.creationTimestamp + ')';
            html += field('Created (approx.)', ds, { copy: false });
        }

        resultPanel.className = 'result-panel success';
        resultPanel.innerHTML = html;
        resultPanel.classList.remove('display-none');

        var btns = resultPanel.querySelectorAll('[data-copy]');
        for (var i = 0; i < btns.length; i++) {
            btns[i].addEventListener('click', function () { copyText(this.getAttribute('data-copy')); });
        }
    }

    function renderFail(msg) {
        resultPanel.className = 'result-panel fail';
        resultPanel.innerHTML = '<div class="result-title">✕ No matching password</div>' +
            '<div class="result-field"><div class="result-value" style="display:block">' + esc(msg) + '</div></div>';
        resultPanel.classList.remove('display-none');
    }

    /* ---------- run ---------- */
    function setRunning(state) {
        running = state;
        runBtn.classList.toggle('display-none', state);
        stopBtn.classList.toggle('display-none', !state);
        clearBtn.disabled = state;
        keysBtn.disabled = state;
        pwBtn.disabled = state;
        pwList.disabled = state;
        kdfInput.disabled = state;
        netSelect.disabled = state;
        if (state) { progressWrap.classList.remove('display-none'); progressBar.classList.remove('indet'); }
    }

    runBtn.addEventListener('click', run);
    stopBtn.addEventListener('click', function () {
        stopRequested = true;
        progressStatus.textContent = 'Stopping…';
    });

    clearBtn.addEventListener('click', function () {
        if (running) return;
        clearOutput();
        output.textContent = fileBytes ? 'File loaded. Enter password and click Run.' : 'Waiting for .keys file and password…';
        progressWrap.classList.add('display-none');
        resultPanel.classList.add('display-none');
        resultPanel.innerHTML = '';
    });

    async function run() {
        if (running) return;
        if (!fileBytes) { showToast('Choose a .keys file first'); return; }

        var passwords = parsePasswords();
        var total = passwords.length;

        var kdf = parseInt(kdfInput.value, 10);
        if (!(kdf >= 1) || kdf > 1000) kdf = 1;
        var netVal = netSelect.value;
        var netOverride = (netVal === 'auto') ? null : parseInt(netVal, 10);

        stopRequested = false;
        setRunning(true);
        resultPanel.classList.add('display-none');
        resultPanel.innerHTML = '';
        progressBar.style.width = '0%';
        clearOutput();
        if (total > 1) log('Testing ' + total + ' passwords (≈ 0.5–1 s each)…', 'log-muted');
        else log('Deriving key via CryptoNight…', 'log-muted');

        var t0 = performance.now();
        var found = null;

        // Derives the ChaCha key + decrypts the outer layer for one password.
        // Throws on a wrong password (JSON parse fails); returns the wallet.
        async function attempt(pw) {
            var key = MK.deriveChachaKey(utf8Bytes(pw), kdf, cnHash);  // heavy: 1 CryptoNight
            var outer = MK.decryptOuter(fileBytes, key);              // throws on a wrong password
            // Correct password found — run the second derivation only now.
            if (Number(outer.obj.encrypted_secret_keys || 0) === 1) {
                progressStatus.textContent = 'Match! Unmasking secret keys (CryptoNight)…';
                await yieldToUI();
            }
            var res = MK.extractKeys(outer.obj, key, cnHash, netOverride, WORDS);
            res.cipher = outer.cipher;
            return res;
        }

        // Always try the empty password first — silently, in the background. A "password-less"
        // wallet is still encrypted with the key from the empty string, so without this
        // a wordlist would never find it. It is not counted in the list/progress
        // that is shown, and is skipped if the list is already just the empty password.
        if (!(total === 1 && passwords[0] === '') && !stopRequested) {
            await yieldToUI();
            try { found = { res: await attempt(''), password: '', index: 0 }; }
            catch (e) { /* no password-less wallet — continue with the list */ }
        }

        for (var i = 0; i < total && !found; i++) {
            if (stopRequested) { log('\nStopped by the user at ' + i + ' of ' + total + '.', 'log-err'); break; }

            var pw = passwords[i];
            var shown = pw === '' ? '(empty password)' : pw;
            var elapsed = (performance.now() - t0) / 1000;
            var status = '[' + (i + 1) + '/' + total + '] testing: ' + shown;
            if (i > 0) {
                var rate = elapsed / i;                 // s per password
                var eta = rate * (total - i);
                status += '   ·   ' + fmtTime(elapsed) + ' elapsed';
                if (total > 1) status += ', ~' + fmtTime(eta) + ' left';
            }
            progressStatus.textContent = status;
            progressBar.style.width = ((i / total) * 100).toFixed(1) + '%';
            await yieldToUI();

            try {
                found = { res: await attempt(pw), password: pw, index: i + 1 };
            } catch (e) {
                // Wrong password → JSON parse failed. Continue.
            }
        }

        progressBar.style.width = '100%';
        var secs = (performance.now() - t0) / 1000;

        if (found) {
            if (found.index === 0) {
                progressStatus.textContent = 'Done — the wallet was password-less (empty password) (' + fmtTime(secs) + ')';
                log('\n✓ MATCH: the wallet is password-less (empty password)', 'log-hit');
            } else {
                progressStatus.textContent = 'Done — password found on attempt ' + found.index + ' of ' + total + ' (' + fmtTime(secs) + ')';
                log('\n✓ MATCH on password #' + found.index + ': ' + (found.password === '' ? '(empty password)' : found.password), 'log-hit');
            }
            if (found.res.mnemonic) log('Seed: ' + found.res.mnemonic, 'log-ok');
            log('Address: ' + found.res.address, 'log-ok');
            renderResult(found.res, found.password, found.index, total);
        } else if (stopRequested) {
            progressStatus.textContent = 'Stopped (' + fmtTime(secs) + ')';
            progressWrap.classList.remove('display-none');
        } else {
            progressStatus.textContent = 'Done — no matching password (' + fmtTime(secs) + ')';
            log('\n✗ None of the ' + total + ' passwords matched.', 'log-err');
            renderFail('Tested ' + total + (total === 1 ? ' password' : ' passwords') + ' with no match. Check the password/list, KDF rounds, and that the file is correct.');
        }

        setRunning(false);
    }

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
})();
