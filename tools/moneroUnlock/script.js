/* =========================================================================
   Monero .keys — plånboksåterställning + dictionary-attack (UI-logik)
   -------------------------------------------------------------------------
   Testar ett eller flera lösenord mot en .keys-fil. Varje försök kräver en
   CryptoNight-hash (~0,5–1 s), så loopen släpper fram en repaint mellan varje
   lösenord (så att Stoppa och progressen fungerar). Rätt lösenord känns igen
   på att ytterlagret dekrypteras till giltig JSON; först då körs den andra
   (tyngre) härledningen för att avmaska de hemliga nycklarna.
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

    /* ---------- hjälp ---------- */
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

    // MessageChannel-yield: släpper fram en repaint utan setTimeout(0):s klämma.
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
        function done() { showToast('Kopierat'); }
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text); done(); });
                return;
            }
        } catch (e) { /* faller igenom */ }
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

    /* ---------- lösenordslista ---------- */
    function parsePasswords() {
        // OBS: trimma inte bort blanksteg — lösenord kan innehålla dem. Ta bort
        // radslut och hoppa bara över helt tomma rader (utom en ensam tom rad,
        // som betyder "lösenordslös plånbok").
        var lines = pwList.value.split('\n').map(function (l) { return l.replace(/\r$/, ''); });
        var nonEmpty = lines.filter(function (l) { return l.length > 0; });
        if (nonEmpty.length === 0 && pwList.value.length === 0) return ['']; // tomt fält → prova tomt lösenord
        if (nonEmpty.length === 0) return ['']; // bara tomma rader → tomt lösenord
        return nonEmpty;
    }
    function updatePwCount() {
        var n = parsePasswords().length;
        var raw = pwList.value.split('\n').filter(function (l) { return l.replace(/\r$/, '').length > 0; }).length;
        pwCount.textContent = raw > 1 ? (raw + ' lösenord') : '';
    }
    pwList.addEventListener('input', updatePwCount);

    /* ---------- filval ---------- */
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
                setKeysName(label, 'valid', 'Ser ut som en giltig .keys-behållare');
                output.textContent = 'Fil inläst. Ange lösenord och klicka på Kör.';
            } catch (e) {
                setKeysName(label, 'invalid', 'Osäker filstruktur: ' + e.message + '. Du kan ändå prova.');
            }
        };
        reader.onerror = function () { fileBytes = null; setKeysName('Kunde inte läsa filen', 'invalid'); };
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
        reader.onerror = function () { pwName.textContent = 'Kunde inte läsa filen'; pwName.classList.remove('set'); };
        reader.readAsText(file);
    });

    /* ---------- resultat-rendering (hela plånboken vid träff) ---------- */
    function field(label, value, opts) {
        opts = opts || {};
        var valHtml = opts.seed ? '<div class="seed-box">' + esc(value) + '</div>' : '<code>' + esc(value) + '</code>';
        var copyBtn = opts.copy === false ? '' : '<button type="button" class="secondary copy-btn" data-copy="' + esc(value) + '">Kopiera</button>';
        var valWrapClass = opts.seed ? 'result-value column' : 'result-value';
        return '<div class="result-field">' +
            '<div class="result-label">' + esc(label) + '</div>' +
            '<div class="' + valWrapClass + '">' + valHtml + copyBtn + '</div>' +
            '</div>';
    }

    function renderResult(r, password, index, total) {
        var html = '';
        html += '<div class="result-title">✓ Plånboken återskapades</div>';

        var tags = '';
        tags += '<span class="tag">' + esc(r.network) + '</span>';
        tags += '<span class="tag">' + esc(r.cipher) + '</span>';
        if (r.watchOnly) tags += '<span class="tag warn">Endast visning</span>';
        else if (r.deterministic) tags += '<span class="tag good">Deterministisk</span>';
        else tags += '<span class="tag warn">Icke-deterministisk</span>';
        html += '<div class="result-field"><div class="result-value" style="display:block">' + tags + '</div></div>';

        if (total > 1) {
            html += field('Lösenord (träff #' + index + ' av ' + total + ')', password);
        } else {
            html += field('Lösenord', password);
        }

        html += field('Primär adress', r.address);

        if (r.mnemonic) {
            html += field('Mnemonic seed (25 ord' + (r.seedLanguage ? ', ' + r.seedLanguage : '') + ')', r.mnemonic, { seed: true });
        } else if (r.watchOnly) {
            html += '<div class="info-box" style="margin:0 0 12px">Detta är en <strong>endast-visning</strong>-plånbok — den innehåller ingen spend-nyckel, så det finns ingen seed-fras att återskapa.</div>';
        } else {
            html += '<div class="info-box" style="margin:0 0 12px">Plånboken är <strong>icke-deterministisk</strong> — en 25-ords-fras skulle inte återskapa samma view-nyckel, så ingen seed visas. Använd nycklarna nedan för att importera plånboken.</div>';
        }

        if (r.spendSecretKey) html += field('Privat spend-nyckel', r.spendSecretKey);
        html += field('Privat view-nyckel', r.viewSecretKey);
        html += field('Publik spend-nyckel', r.spendPublicKey);
        html += field('Publik view-nyckel', r.viewPublicKey);

        if (r.creationTimestamp) {
            var d = new Date(r.creationTimestamp * 1000);
            var ds = isNaN(d.getTime()) ? String(r.creationTimestamp) : d.toISOString().slice(0, 10) + ' (' + r.creationTimestamp + ')';
            html += field('Skapad (ungefär)', ds, { copy: false });
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
        resultPanel.innerHTML = '<div class="result-title">✕ Inget matchande lösenord</div>' +
            '<div class="result-field"><div class="result-value" style="display:block">' + esc(msg) + '</div></div>';
        resultPanel.classList.remove('display-none');
    }

    /* ---------- körning ---------- */
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
        progressStatus.textContent = 'Stoppar…';
    });

    clearBtn.addEventListener('click', function () {
        if (running) return;
        clearOutput();
        output.textContent = fileBytes ? 'Fil inläst. Ange lösenord och klicka på Kör.' : 'Väntar på .keys-fil och lösenord…';
        progressWrap.classList.add('display-none');
        resultPanel.classList.add('display-none');
        resultPanel.innerHTML = '';
    });

    async function run() {
        if (running) return;
        if (!fileBytes) { showToast('Välj en .keys-fil först'); return; }

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
        if (total > 1) log('Testar ' + total + ' lösenord (≈ 0,5–1 s vardera)…', 'log-muted');
        else log('Härleder nyckel via CryptoNight…', 'log-muted');

        var t0 = performance.now();
        var found = null;

        for (var i = 0; i < total; i++) {
            if (stopRequested) { log('\nStoppad av användaren vid ' + i + ' av ' + total + '.', 'log-err'); break; }

            var pw = passwords[i];
            var shown = pw === '' ? '(tomt lösenord)' : pw;
            var elapsed = (performance.now() - t0) / 1000;
            var status = '[' + (i + 1) + '/' + total + '] testar: ' + shown;
            if (i > 0) {
                var rate = elapsed / i;                 // s per lösenord
                var eta = rate * (total - i);
                status += '   ·   ' + fmtTime(elapsed) + ' förflutet';
                if (total > 1) status += ', ~' + fmtTime(eta) + ' kvar';
            }
            progressStatus.textContent = status;
            progressBar.style.width = ((i / total) * 100).toFixed(1) + '%';
            await yieldToUI();

            try {
                var pwBytes = utf8Bytes(pw);
                var key = MK.deriveChachaKey(pwBytes, kdf, cnHash);   // tung: 1 CryptoNight
                var outer = MK.decryptOuter(fileBytes, key);          // kastar vid fel lösenord
                // Rätt lösenord hittat — kör den andra härledningen bara nu.
                if (Number(outer.obj.encrypted_secret_keys || 0) === 1) {
                    progressStatus.textContent = 'Träff! Avmaskar hemliga nycklar (CryptoNight)…';
                    await yieldToUI();
                }
                var res = MK.extractKeys(outer.obj, key, cnHash, netOverride, WORDS);
                res.cipher = outer.cipher;
                found = { res: res, password: pw, index: i + 1 };
                break;
            } catch (e) {
                // Fel lösenord → JSON-parse misslyckades. Fortsätt.
            }
        }

        progressBar.style.width = '100%';
        var secs = (performance.now() - t0) / 1000;

        if (found) {
            progressStatus.textContent = 'Klar — lösenord hittat på försök ' + found.index + ' av ' + total + ' (' + fmtTime(secs) + ')';
            log('\n✓ MATCH på lösenord #' + found.index + ': ' + (found.password === '' ? '(tomt lösenord)' : found.password), 'log-hit');
            if (found.res.mnemonic) log('Seed: ' + found.res.mnemonic, 'log-ok');
            log('Adress: ' + found.res.address, 'log-ok');
            renderResult(found.res, found.password, found.index, total);
        } else if (stopRequested) {
            progressStatus.textContent = 'Stoppad (' + fmtTime(secs) + ')';
            progressWrap.classList.remove('display-none');
        } else {
            progressStatus.textContent = 'Klar — inget matchande lösenord (' + fmtTime(secs) + ')';
            log('\n✗ Inget av de ' + total + ' lösenorden matchade.', 'log-err');
            renderFail('Testade ' + total + (total === 1 ? ' lösenord' : ' lösenord') + ' utan träff. Kontrollera lösenordet/listan, KDF-rundor och att filen är rätt.');
        }

        setRunning(false);
    }

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
})();
