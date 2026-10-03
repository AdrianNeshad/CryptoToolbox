'use strict';
(function () {
  var $ = function (id) { return document.getElementById(id); };

  // ---- DOM ------------------------------------------------------------------
  var folderBtn = $('folder-btn'), folderInput = $('folder-input'), folderName = $('folder-name');
  var deviceInfo = $('device-info');
  var pwInput = $('pw-input'), pwToggle = $('pw-toggle');
  var runBtn = $('run-btn'), exportBtn = $('export-btn'), clearBtn = $('clear-btn');
  var progWrap = $('progress-wrap'), progBar = $('progress-bar'), progStatus = $('progress-status');
  var resultPanel = $('result-panel'), resultTitle = $('result-title'), resultBody = $('result-body');
  var kcToolbar = $('kc-toolbar'), kcSearch = $('kc-search'), kcTabs = $('kc-tabs'), kcList = $('kc-list');
  var out = $('output'), toast = $('toast');

  // ---- State ----------------------------------------------------------------
  var fileMap = null;          // lowercased relpath -> File
  var manifestInfo = null;     // { deviceName, isEncrypted, ... }
  var sqlPromise = null;
  var lastResult = null;       // { General, Internet, Certs, Keys, ... }
  var flatEntries = [];        // [{ cat, rec }]
  var activeTab = 'all';
  var toastTimer = null;

  // ---- Small helpers --------------------------------------------------------
  function log(msg, cls) {
    var span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = msg + '\n';
    out.appendChild(span);
    out.scrollTop = out.scrollHeight;
  }
  function clearLog() { out.textContent = ''; }
  function showToast(msg) {
    toast.textContent = msg; toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toast.classList.remove('show'); }, 1800);
  }
  function setProgress(text, indeterminate) {
    progWrap.classList.remove('display-none');
    progStatus.textContent = text || '';
    if (indeterminate) progBar.classList.add('indet'); else progBar.classList.remove('indet');
  }
  function hideProgress() { progWrap.classList.add('display-none'); progBar.classList.remove('indet'); }

  function toHex(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
    return s;
  }
  function tryUtf8(u8) {
    // returns a string if the bytes look like printable text, else null
    if (!u8.length) return '';
    var printable = 0;
    for (var i = 0; i < u8.length; i++) {
      var c = u8[i];
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c !== 127)) printable++;
    }
    if (printable / u8.length < 0.85) return null;
    try {
      var s = new TextDecoder('utf-8', { fatal: true }).decode(u8);
      return s;
    } catch (e) { return null; }
  }

  // ---- Folder selection -----------------------------------------------------
  folderBtn.addEventListener('click', function () { folderInput.click(); });
  folderInput.addEventListener('change', function () {
    var files = folderInput.files;
    if (!files || !files.length) return;
    fileMap = {};
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      var rel = f.webkitRelativePath || f.name;
      // strip the first path segment (the chosen folder's own name)
      var slash = rel.indexOf('/');
      var key = slash >= 0 ? rel.slice(slash + 1) : rel;
      fileMap[key.toLowerCase()] = f;
    }
    var rootName = (files[0].webkitRelativePath || '').split('/')[0] || 'folder';
    folderName.textContent = rootName + ' (' + files.length + ' files)';
    folderName.className = 'file-name set';
    inspectManifest();
  });

  function getFile(relpath) {
    if (!fileMap) return null;
    return fileMap[String(relpath).toLowerCase()] || null;
  }
  function getBytes(relpath) {
    var f = getFile(relpath);
    if (!f) return Promise.resolve(null);
    return f.arrayBuffer().then(function (ab) { return new Uint8Array(ab); });
  }

  // Peek at Manifest.plist to show the device name / encryption state.
  function inspectManifest() {
    deviceInfo.classList.add('display-none');
    manifestInfo = null;
    getBytes('Manifest.plist').then(function (bytes) {
      if (!bytes) {
        deviceInfo.innerHTML = '<span class="log-err">No Manifest.plist in this folder. Pick the backup folder that directly contains Manifest.plist and Manifest.db.</span>';
        deviceInfo.classList.remove('display-none');
        return;
      }
      try {
        manifestInfo = window.KC.backup.parseManifest(bytes);
      } catch (e) {
        deviceInfo.innerHTML = '<span class="log-err">Could not read Manifest.plist: ' + esc(e.message) + '</span>';
        deviceInfo.classList.remove('display-none');
        return;
      }
      var enc = manifestInfo.isEncrypted;
      var html = '<span class="di-name">' + esc(manifestInfo.deviceName || 'iOS device') + '</span>';
      if (manifestInfo.productVersion) html += ' <span class="log-muted">iOS ' + esc(manifestInfo.productVersion) + '</span>';
      html += '<span class="di-badge ' + (enc ? 'enc' : 'plain') + '">' + (enc ? 'Encrypted' : 'Not encrypted') + '</span>';
      if (!enc) html += '<div class="hint" style="margin-top:6px">iOS only stores the keychain inside encrypted backups. Re-create this backup with “Encrypt local backup” enabled.</div>';
      deviceInfo.innerHTML = html;
      deviceInfo.classList.remove('display-none');
      if (enc) pwInput.focus();
    });
  }

  // ---- Password show/hide ---------------------------------------------------
  pwToggle.addEventListener('click', function () {
    var show = pwInput.type === 'password';
    pwInput.type = show ? 'text' : 'password';
    pwToggle.textContent = show ? 'Hide' : 'Show';
  });
  pwInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') runBtn.click(); });

  // ---- sql.js ---------------------------------------------------------------
  function ensureSQL() {
    if (sqlPromise) return sqlPromise;
    if (typeof initSqlJs !== 'function') return Promise.reject(new Error('sql.js failed to load.'));
    sqlPromise = initSqlJs({ wasmBinary: window.SQL_WASM_BINARY });
    return sqlPromise;
  }

  // ---- Run ------------------------------------------------------------------
  runBtn.addEventListener('click', function () {
    if (!fileMap) { showToast('Choose a backup folder first.'); return; }
    runBtn.disabled = true;
    exportBtn.classList.add('display-none');
    resultPanel.classList.add('display-none');
    kcToolbar.classList.add('display-none');
    kcList.innerHTML = '';
    out.classList.remove('display-none'); // show the live log while running
    clearLog();
    setProgress('Starting…', true);
    log('Opening keychain…', 'log-muted');

    ensureSQL().then(function (SQL) {
      return window.KC.backup.loadKeychain({
        getBytes: getBytes,
        password: pwInput.value,
        SQL: SQL,
        onProgress: function (m) { setProgress(m, true); log(m, 'log-muted'); }
      });
    }).then(function (res) {
      lastResult = res;
      hideProgress();
      renderResult(res);
      out.classList.add('display-none'); // hide the progress log once done
    }).catch(function (err) {
      hideProgress();
      renderError(err);
      out.classList.remove('display-none'); // keep the log visible on error
      log('Error: ' + err.message, 'log-err');
    }).then(function () { runBtn.disabled = false; });
  });

  function renderError(err) {
    resultPanel.className = 'result-panel fail';
    resultTitle.textContent = err && err.needsPassword ? 'Password required' : 'Could not open keychain';
    resultBody.innerHTML = esc(err ? err.message : 'Unknown error');
    resultPanel.classList.remove('display-none');
  }

  // ---- Result rendering -----------------------------------------------------
  var CATS = [
    { key: 'General', code: 'genp', label: 'Passwords' },
    { key: 'Internet', code: 'inet', label: 'Internet' },
    { key: 'Certs', code: 'cert', label: 'Certificates' },
    { key: 'Keys', code: 'keys', label: 'Keys' }
  ];

  function renderResult(res) {
    flatEntries = [];
    CATS.forEach(function (c) {
      (res[c.key] || []).forEach(function (rec) { flatEntries.push({ cat: c, rec: rec }); });
    });

    resultPanel.className = 'result-panel success';
    resultTitle.textContent = 'Keychain opened — ' + (res.deviceName || 'iOS device');
    var counts = '<div class="result-counts">';
    CATS.forEach(function (c) {
      counts += '<span class="count-chip">' + c.label + ' <b>' + (res[c.key] || []).length + '</b></span>';
    });
    counts += '<span class="count-chip">Total <b>' + flatEntries.length + '</b></span></div>';
    resultBody.innerHTML = counts;
    resultPanel.classList.remove('display-none');
    exportBtn.classList.remove('display-none');

    // tabs
    activeTab = 'all';
    var tabs = [{ id: 'all', label: 'All', n: flatEntries.length }];
    CATS.forEach(function (c) { tabs.push({ id: c.code, label: c.label, n: (res[c.key] || []).length }); });
    kcTabs.innerHTML = tabs.map(function (t) {
      return '<button class="kc-tab' + (t.id === 'all' ? ' active' : '') + '" data-tab="' + t.id + '">' +
        esc(t.label) + '<span class="kc-tab-n">' + t.n + '</span></button>';
    }).join('');
    kcSearch.value = '';
    kcToolbar.classList.remove('display-none');
    renderList();
  }

  kcTabs.addEventListener('click', function (e) {
    var b = e.target.closest('.kc-tab'); if (!b) return;
    activeTab = b.getAttribute('data-tab');
    Array.prototype.forEach.call(kcTabs.children, function (c) { c.classList.toggle('active', c === b); });
    renderList();
  });
  kcSearch.addEventListener('input', function () { renderList(); });

  function entryTitle(cat, rec) {
    if (cat.code === 'inet') return str(rec.srvr) || str(rec.labl) || str(rec.acct) || '(internet password)';
    // genp: lead with the account; the service / bundle id becomes the subtitle.
    if (cat.code === 'genp') return str(rec.acct) || str(rec.labl) || str(rec.svce) || '(generic password)';
    if (cat.code === 'cert') return str(rec.labl) || str(rec.subj) || '(certificate)';
    return str(rec.labl) || '(key)';
  }
  function entrySub(cat, rec) {
    var bits = [];
    if (cat.code === 'genp') {
      if (str(rec.svce)) bits.push(str(rec.svce));
      if (str(rec.agrp) && str(rec.agrp) !== str(rec.svce)) bits.push(str(rec.agrp));
    } else if (cat.code === 'inet') {
      if (str(rec.acct)) bits.push(str(rec.acct));
      if (rec.ptcl != null) bits.push(str(rec.ptcl));
      if (rec.port) bits.push(':' + rec.port);
    } else {
      if (str(rec.acct)) bits.push(str(rec.acct));
    }
    return bits.join(' · ');
  }

  function filtered() {
    var q = kcSearch.value.trim().toLowerCase();
    return flatEntries.filter(function (e) {
      if (activeTab !== 'all' && e.cat.code !== activeTab) return false;
      if (!q) return true;
      return searchBlob(e).indexOf(q) >= 0;
    });
  }
  function searchBlob(e) {
    if (e._blob) return e._blob;
    var parts = [e.cat.label];
    for (var k in e.rec) {
      if (!e.rec.hasOwnProperty(k) || k.charAt(0) === '_') continue;
      if (k === 'data') continue; // don't search secrets
      var v = e.rec[k];
      if (typeof v === 'string') parts.push(v);
      else if (typeof v === 'number') parts.push(String(v));
    }
    e._blob = parts.join(' ').toLowerCase();
    return e._blob;
  }

  function renderList() {
    var items = filtered();
    if (!items.length) {
      kcList.innerHTML = '<div class="kc-empty">No matching entries.</div>';
      return;
    }
    var html = '';
    for (var i = 0; i < items.length; i++) {
      var e = items[i];
      var idx = flatEntries.indexOf(e);
      html += '<div class="kc-entry" data-idx="' + idx + '">' +
        '<div class="kc-entry-head">' +
          '<span class="kc-cat ' + e.cat.code + '">' + e.cat.code + '</span>' +
          '<span class="kc-main"><span class="kc-title">' + esc(entryTitle(e.cat, e.rec)) + '</span>' +
          '<span class="kc-sub">' + esc(entrySub(e.cat, e.rec)) + '</span></span>' +
          '<span class="kc-chev">▶</span>' +
        '</div>' +
        '<div class="kc-detail"></div>' +
      '</div>';
    }
    kcList.innerHTML = html;
  }

  // expand / collapse + lazy detail render
  kcList.addEventListener('click', function (e) {
    var mini = e.target.closest('.kc-mini');
    if (mini) { handleMini(mini); return; }
    var head = e.target.closest('.kc-entry-head');
    if (!head) return;
    var entry = head.parentNode;
    var open = entry.classList.toggle('open');
    if (open) {
      var detail = entry.querySelector('.kc-detail');
      if (!detail.getAttribute('data-filled')) {
        detail.innerHTML = renderDetail(flatEntries[+entry.getAttribute('data-idx')].rec);
        detail.setAttribute('data-filled', '1');
      }
    }
  });

  var FIELD_LABELS = {
    acct: 'Account', svce: 'Service', srvr: 'Server', labl: 'Label', desc: 'Description',
    agrp: 'Access group', gena: 'Generic', data: 'Secret', ptcl: 'Protocol', port: 'Port',
    path: 'Path', atyp: 'Auth type', sdmn: 'Security domain', pdmn: 'Protection class',
    cdat: 'Created', mdat: 'Modified', sync: 'iCloud sync', tomb: 'Tombstone',
    musr: 'Multi-user', sha1: 'SHA-1', subj: 'Subject', issr: 'Issuer', slnr: 'Serial',
    skid: 'Subject key ID', type: 'Type', bsiz: 'Key size', crtr: 'Creator',
    cenc: 'Can encrypt', esiz: 'Effective key size', klbl: 'Key label', pcss: 'Persistent',
    vwht: 'View hint', accc: 'Access control'
  };
  var FIELD_ORDER = ['data', 'acct', 'agrp', 'svce', 'srvr', 'ptcl', 'port', 'path', 'labl', 'desc', 'gena'];

  function renderDetail(rec) {
    var keys = Object.keys(rec).filter(function (k) { return k.charAt(0) !== '_'; });
    keys.sort(function (a, b) {
      var ia = FIELD_ORDER.indexOf(a), ib = FIELD_ORDER.indexOf(b);
      if (ia < 0) ia = 99; if (ib < 0) ib = 99;
      if (ia !== ib) return ia - ib;
      return a < b ? -1 : 1;
    });
    if (rec.__error) {
      return '<div class="kc-field"><div class="kc-field-k">Status</div><div class="kc-field-v"><span class="kc-vtext log-err">' + esc(rec.__error) + '</span></div></div>';
    }
    var html = '';
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var label = FIELD_LABELS[k] || k;
      var codeTag = FIELD_LABELS[k] ? ' <span class="kc-code">' + esc(k) + '</span>' : '';
      html += '<div class="kc-field"><div class="kc-field-k">' + esc(label) + codeTag + '</div>' +
        '<div class="kc-field-v' + (k === 'data' ? ' kc-secret' : '') + '">' + renderValue(k, rec[k]) + '</div></div>';
    }
    return html;
  }

  function renderValue(key, v) {
    if (v == null) return '<span class="kc-vtext log-muted">(null)</span>';
    if (typeof v === 'boolean') return '<span class="kc-vtext">' + (v ? 'Yes' : 'No') + '</span>';
    if (typeof v === 'number') return '<span class="kc-vtext">' + esc(String(v)) + '</span>';
    if (typeof v === 'string') return '<span class="kc-vtext">' + esc(v) + '</span>' + copyBtn(v);
    if (v && v.__asn1time) return '<span class="kc-vtext">' + esc(fmtAsn1Time(v.__asn1time)) + '</span>';
    if (v && typeof v.__nsdate === 'number') return '<span class="kc-vtext">' + esc(fmtNsDate(v.__nsdate)) + '</span>';
    if (v instanceof Uint8Array) {
      var hex = toHex(v);
      var text = tryUtf8(v);
      var isSecret = key === 'data';
      if (isSecret) {
        // masked by default
        var payload = text != null ? text : hex;
        return '<span class="kc-vtext" data-secret="' + esc(payload) + '" data-mode="' + (text != null ? 'text' : 'hex') + '">••••••••</span>' +
          '<button class="kc-mini" data-act="reveal">Reveal</button>' +
          '<button class="kc-mini" data-act="copy" data-copy="' + esc(payload) + '">Copy</button>';
      }
      if (text != null) {
        return '<span class="kc-vtext">' + esc(text) + '</span>' + copyBtn(text) +
          '<button class="kc-mini" data-act="togglehex" data-hex="' + esc(hex) + '" data-text="' + esc(text) + '">Hex</button>';
      }
      return '<span class="kc-vtext kc-hex">' + esc(hex) + '</span>' + copyBtn(hex);
    }
    if (Array.isArray(v)) return '<span class="kc-vtext log-muted">[' + v.length + ' items]</span>';
    return '<span class="kc-vtext log-muted">' + esc(String(v)) + '</span>';
  }

  function copyBtn(val) { return '<button class="kc-mini" data-act="copy" data-copy="' + esc(val) + '">Copy</button>'; }

  function handleMini(btn) {
    var act = btn.getAttribute('data-act');
    var vtext = btn.parentNode.querySelector('.kc-vtext');
    if (act === 'copy') {
      copyText(btn.getAttribute('data-copy'));
    } else if (act === 'reveal') {
      if (vtext.getAttribute('data-revealed')) {
        vtext.textContent = '••••••••'; vtext.removeAttribute('data-revealed'); btn.textContent = 'Reveal';
      } else {
        vtext.textContent = vtext.getAttribute('data-secret'); vtext.setAttribute('data-revealed', '1'); btn.textContent = 'Hide';
      }
    } else if (act === 'togglehex') {
      if (vtext.getAttribute('data-ishex')) {
        vtext.textContent = btn.getAttribute('data-text'); vtext.classList.remove('kc-hex'); vtext.removeAttribute('data-ishex'); btn.textContent = 'Hex';
      } else {
        vtext.textContent = btn.getAttribute('data-hex'); vtext.classList.add('kc-hex'); vtext.setAttribute('data-ishex', '1'); btn.textContent = 'Text';
      }
    }
  }

  function copyText(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).then(function () { showToast('Copied'); }, function () { legacyCopy(t); });
    } else { legacyCopy(t); }
  }
  function legacyCopy(t) {
    var ta = document.createElement('textarea'); ta.value = t; document.body.appendChild(ta);
    ta.select(); try { document.execCommand('copy'); showToast('Copied'); } catch (e) {} document.body.removeChild(ta);
  }

  // ---- Export ---------------------------------------------------------------
  exportBtn.addEventListener('click', function () {
    if (!lastResult) return;
    var dump = { device: lastResult.deviceName, iosVersion: lastResult.productVersion, categories: {} };
    CATS.forEach(function (c) {
      dump.categories[c.label] = (lastResult[c.key] || []).map(serializeRec);
    });
    var blob = new Blob([JSON.stringify(dump, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'keychain-' + (lastResult.deviceName || 'ios').replace(/[^\w.-]+/g, '_') + '.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    showToast('Exported JSON');
  });

  function serializeRec(rec) {
    var o = {};
    for (var k in rec) {
      if (!rec.hasOwnProperty(k) || k.charAt(0) === '_') continue;
      o[k] = serializeVal(rec[k]);
    }
    if (rec.__error) o._error = rec.__error;
    return o;
  }
  function serializeVal(v) {
    if (v instanceof Uint8Array) { var t = tryUtf8(v); return t != null ? t : { hex: toHex(v) }; }
    if (v && v.__asn1time) return fmtAsn1Time(v.__asn1time);
    if (v && typeof v.__nsdate === 'number') return fmtNsDate(v.__nsdate);
    if (Array.isArray(v)) return v.map(serializeVal);
    return v;
  }

  // ---- Dates / misc ---------------------------------------------------------
  function fmtAsn1Time(s) {
    // UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ
    var m = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?/.exec(s);
    if (!m) return s;
    var yr = m[1].length === 2 ? (parseInt(m[1], 10) >= 50 ? '19' + m[1] : '20' + m[1]) : m[1];
    return yr + '-' + m[2] + '-' + m[3] + ' ' + m[4] + ':' + m[5] + ':' + (m[6] || '00') + ' UTC';
  }
  function fmtNsDate(sec) {
    try { return new Date(sec * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC'); }
    catch (e) { return String(sec); }
  }
  function str(v) { return typeof v === 'string' ? v : (v == null ? '' : (typeof v === 'number' ? String(v) : '')); }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // ---- Clear ----------------------------------------------------------------
  clearBtn.addEventListener('click', function () {
    lastResult = null; flatEntries = [];
    kcList.innerHTML = ''; kcToolbar.classList.add('display-none');
    resultPanel.classList.add('display-none'); exportBtn.classList.add('display-none');
    hideProgress();
    out.classList.remove('display-none');
    out.textContent = 'Waiting to run…';
    pwInput.value = '';
  });

  // ---- Live theme switching from the Toolbox shell --------------------------
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
