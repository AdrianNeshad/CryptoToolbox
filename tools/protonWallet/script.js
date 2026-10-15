(function () {
  'use strict';

  var userKeyEl = document.getElementById('user-key');
  var passphraseEl = document.getElementById('passphrase');
  var walletKeyEl = document.getElementById('wallet-key');
  var mnemonicEl = document.getElementById('mnemonic-key');
  var runBtn = document.getElementById('run-btn');
  var clearBtn = document.getElementById('clear-btn');
  var pwToggle = document.getElementById('pw-toggle');
  var resultsEl = document.getElementById('results');
  var logEl = document.getElementById('log');
  var toastEl = document.getElementById('toast');

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  var toastTimer = null;
  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.remove('show'); }, 1800);
  }

  function resetLog() { logEl.textContent = ''; logEl.classList.add('display-none'); }
  function appendLog(line) {
    logEl.classList.remove('display-none');
    logEl.textContent += (logEl.textContent ? '\n' : '') + line;
    logEl.scrollTop = logEl.scrollHeight;
  }

  pwToggle.addEventListener('click', function () {
    var show = passphraseEl.type === 'password';
    passphraseEl.type = show ? 'text' : 'password';
    pwToggle.textContent = show ? 'Hide' : 'Show';
  });

  function renderResults(results) {
    resultsEl.innerHTML = '';
    results.forEach(function (r) {
      var card = document.createElement('div');
      card.className = 'result-card ' + (r.ok ? 'ok' : 'fail');

      var head = '<div class="result-card-head">';
      head += '<span class="result-label">' + esc(r.label) + '</span>';
      if (r.ok) {
        head += '<span class="badge ok">decrypted</span>';
        head += '<span class="badge">' + esc(r.method) + '</span>';
        if (!r.valid) head += '<span class="badge warn">unexpected format</span>';
      } else {
        head += '<span class="badge fail">failed</span>';
      }
      head += '</div>';

      var body = '';
      if (r.ok) {
        body += '<div class="mnemonic-box" id="mn-' + encodeURIComponent(r.label) + '">' + esc(r.mnemonic) + '</div>';
        body += '<div class="mnemonic-actions"><button type="button" class="secondary copy-btn">Copy phrase</button></div>';
        if (!r.valid) {
          body += '<div class="result-warn">The decryption succeeded and the authentication tag verified, ' +
            'but the result does not look like a standard 12&ndash;24 word BIP39 phrase. Shown exactly as decrypted.</div>';
        }
      } else {
        body += '<div class="result-error">' + esc(r.error) + '</div>';
      }

      card.innerHTML = head + body;
      if (r.ok) {
        card.querySelector('.copy-btn').addEventListener('click', function () {
          copyText(r.mnemonic);
        });
      }
      resultsEl.appendChild(card);
    });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast('Copied'); },
        function () { fallbackCopy(text); });
    } else {
      fallbackCopy(text);
    }
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); toast('Copied'); } catch (e) { toast('Copy failed'); }
    document.body.removeChild(ta);
  }

  runBtn.addEventListener('click', async function () {
    resultsEl.innerHTML = '';
    resetLog();
    runBtn.disabled = true;
    var oldLabel = runBtn.textContent;
    runBtn.textContent = 'Decrypting…';
    try {
      var results = await window.ProtonWallet.decryptAll({
        userKeysText: userKeyEl.value,
        passphrase: passphraseEl.value,
        walletKeysText: walletKeyEl.value,
        mnemonicsText: mnemonicEl.value,
        onLog: appendLog,
      });
      renderResults(results);
      var okCount = results.filter(function (r) { return r.ok; }).length;
      if (okCount === 0) toast('No mnemonic could be decrypted');
      else toast('Recovered ' + okCount + ' mnemonic' + (okCount > 1 ? 's' : ''));
    } catch (e) {
      appendLog('Error: ' + e.message);
      resultsEl.innerHTML = '<div class="result-card fail"><div class="result-error">' + esc(e.message) + '</div></div>';
      toast('Could not decrypt');
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = oldLabel;
    }
  });

  clearBtn.addEventListener('click', function () {
    userKeyEl.value = '';
    passphraseEl.value = '';
    walletKeyEl.value = '';
    mnemonicEl.value = '';
    resultsEl.innerHTML = '';
    resetLog();
    passphraseEl.type = 'password';
    pwToggle.textContent = 'Show';
  });

  // Live theme switching from the Toolbox shell
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
