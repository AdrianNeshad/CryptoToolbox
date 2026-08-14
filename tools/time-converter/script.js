const APPLE_EPOCH_MS = Date.UTC(2001, 0, 1); // 978307200000
const WINDOWS_EPOCH_MS = Date.UTC(1601, 0, 1); // -11644473600000

const rawInput = document.getElementById('raw-input');
const formatSelect = document.getElementById('format-select');
const statusEl = document.getElementById('status');
const guessEl = document.getElementById('guess');
const matrixEl = document.getElementById('matrix');
const matrixRows = document.getElementById('matrix-rows');
const interpretationsEl = document.getElementById('interpretations');
const interpretationRows = document.getElementById('interpretation-rows');
const toast = document.getElementById('toast');

const FORMAT_LABELS = {
    'unix-s': 'Unix (sekunder)',
    'unix-ms': 'Unix (ms)',
    'unix-us': 'Unix (µs)',
    'unix-ns': 'Unix (ns)',
    apple: 'Apple Cocoa / NSDate',
    webkit: 'WebKit / Chrome',
    filetime: 'Windows FILETIME',
    iso: 'ISO 8601',
};

function setStatus(msg, isError) {
    statusEl.textContent = msg;
    statusEl.style.color = isError ? 'var(--error)' : 'var(--text-muted)';
}

function showToast() {
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 1200);
}

function pad(n) {
    return String(n).padStart(2, '0');
}

function formatLocal(date) {
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
        `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${String(date.getMilliseconds()).padStart(3, '0')}`;
}

function cleanNumeric(raw) {
    return String(raw).trim().replace(/[_\s,]/g, '');
}

function parseNumber(raw) {
    const cleaned = cleanNumeric(raw);
    if (!/^-?\d+(\.\d+)?$/.test(cleaned)) return null;
    const n = Number(cleaned);
    return Number.isFinite(n) ? n : null;
}

function fromUnixSeconds(n) { return new Date(n * 1000); }
function fromUnixMs(n) { return new Date(n); }
function fromUnixUs(n) { return new Date(n / 1000); }
function fromUnixNs(n) { return new Date(n / 1e6); }
function fromApple(n) { return new Date(APPLE_EPOCH_MS + n * 1000); }
function fromWebkit(n) { return new Date(WINDOWS_EPOCH_MS + n / 1000); }
function fromFiletime(n) { return new Date(WINDOWS_EPOCH_MS + n / 10000); }

function toFormats(date) {
    const ms = date.getTime();
    return {
        utc: date.toUTCString(),
        local: formatLocal(date),
        iso: date.toISOString(),
        'unix-s': String(Math.trunc(ms / 1000)),
        'unix-ms': String(Math.trunc(ms)),
        'unix-us': String(Math.trunc(ms * 1000)),
        'unix-ns': String(Math.trunc(ms * 1e6)),
        apple: String((ms - APPLE_EPOCH_MS) / 1000),
        webkit: String(Math.trunc((ms - WINDOWS_EPOCH_MS) * 1000)),
        filetime: String(Math.trunc((ms - WINDOWS_EPOCH_MS) * 10000)),
    };
}

/** Heuristic auto-detect for numeric timestamps. */
function detectFormat(n, raw) {
    const abs = Math.abs(n);
    const digits = cleanNumeric(raw).replace(/^-/, '').replace(/\.\d+$/, '').length;
    const asUnixS = fromUnixSeconds(n);
    const asApple = fromApple(n);
    const yearUnix = asUnixS.getUTCFullYear();
    const yearApple = asApple.getUTCFullYear();

    // FILETIME ~ 18 digits, values ~ 1e17–1.4e18 for modern dates
    if (digits >= 17 && abs >= 1e16 && abs < 1e19) {
        const asFt = fromFiletime(n);
        const y = asFt.getUTCFullYear();
        if (y >= 1980 && y <= 2100) {
            return { format: 'filetime', reason: 'Ser ut som Windows FILETIME (100 ns sedan 1601).' };
        }
    }

    // WebKit µs ~ 16–17 digits
    if (digits >= 15 && abs >= 1e14 && abs < 1e18) {
        const asWk = fromWebkit(n);
        const y = asWk.getUTCFullYear();
        if (y >= 1980 && y <= 2100) {
            return { format: 'webkit', reason: 'Ser ut som WebKit/Chrome (µs sedan 1601).' };
        }
    }

    // Unix ns
    if (digits >= 18 && abs >= 1e17) {
        return { format: 'unix-ns', reason: 'Mycket stort tal — tolkas som Unix-nanosekunder.' };
    }

    // Unix µs
    if (digits >= 15 && digits <= 16) {
        return { format: 'unix-us', reason: 'Tolkas som Unix-mikrosekunder.' };
    }

    // Unix ms
    if (digits >= 12 && digits <= 14) {
        return { format: 'unix-ms', reason: 'Tolkas som Unix-millisekunder.' };
    }

    // Ambiguous seconds-scale: Unix vs Apple Cocoa
    if (digits <= 11) {
        const unixPlausible = yearUnix >= 1995 && yearUnix <= 2100;
        const applePlausible = yearApple >= 1995 && yearApple <= 2100;

        // Typical Cocoa for 2015–2030 is ~4.4e8–9.5e8; Unix is ~1.4e9–1.9e9
        if (abs >= 1.2e9 && abs < 4e9 && unixPlausible) {
            return { format: 'unix-s', reason: 'Tolkas som Unix-sekunder (vanligt i loggar).' };
        }
        if (abs < 1.2e9 && applePlausible) {
            return {
                format: 'apple',
                reason: 'Tolkas som Apple Cocoa/NSDate (s sedan 2001) — vanligt i iOS SQLite. Jämför även Unix-sekunder i listan nedan.',
            };
        }
        if (unixPlausible) {
            return { format: 'unix-s', reason: 'Tolkas som Unix-sekunder.' };
        }
        if (applePlausible) {
            return { format: 'apple', reason: 'Tolkas som Apple Cocoa/NSDate.' };
        }
    }

    return { format: 'unix-s', reason: 'Kunde inte avgöra säkert — faller tillbaka på Unix-sekunder. Använd listan “Om råvärdet tolkas som…”.' };
}

function dateFromFormat(format, raw) {
    if (format === 'iso') {
        const d = new Date(String(raw).trim());
        return Number.isNaN(d.getTime()) ? null : d;
    }
    const n = parseNumber(raw);
    if (n === null) return null;
    switch (format) {
        case 'unix-s': return fromUnixSeconds(n);
        case 'unix-ms': return fromUnixMs(n);
        case 'unix-us': return fromUnixUs(n);
        case 'unix-ns': return fromUnixNs(n);
        case 'apple': return fromApple(n);
        case 'webkit': return fromWebkit(n);
        case 'filetime': return fromFiletime(n);
        default: return null;
    }
}

function isPlausibleDate(date) {
    if (!date || Number.isNaN(date.getTime())) return false;
    const y = date.getUTCFullYear();
    return y >= 1990 && y <= 2038;
}

function rowHtml(label, value, meta, plausible) {
    const id = 'v-' + Math.random().toString(36).slice(2, 9);
    return `
      <div class="result-row${plausible ? ' plausible' : ''}">
        <span class="label">${label}</span>
        <div class="value-block">
          <code id="${id}">${escapeHtml(value)}</code>
          ${meta ? `<span class="meta">${escapeHtml(meta)}</span>` : ''}
        </div>
        <button type="button" class="copy-btn secondary" data-copy-id="${id}">Kopiera</button>
      </div>`;
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function renderMatrix(date) {
    const f = toFormats(date);
    matrixRows.innerHTML = [
        rowHtml('UTC', f.utc),
        rowHtml('Lokal', f.local),
        rowHtml('ISO 8601', f.iso),
        rowHtml('Unix (s)', f['unix-s']),
        rowHtml('Unix (ms)', f['unix-ms']),
        rowHtml('Unix (µs)', f['unix-us']),
        rowHtml('Unix (ns)', f['unix-ns']),
        rowHtml('Apple Cocoa / NSDate', f.apple, 'sekunder sedan 2001-01-01 UTC'),
        rowHtml('WebKit / Chrome', f.webkit, 'mikrosekunder sedan 1601-01-01 UTC'),
        rowHtml('Windows FILETIME', f.filetime, '100 ns sedan 1601-01-01 UTC'),
    ].join('');
    matrixEl.classList.remove('display-none');
}

function renderInterpretations(raw) {
    const n = parseNumber(raw);
    if (n === null) {
        interpretationsEl.classList.add('display-none');
        return;
    }

    const candidates = [
        ['unix-s', fromUnixSeconds(n)],
        ['unix-ms', fromUnixMs(n)],
        ['unix-us', fromUnixUs(n)],
        ['unix-ns', fromUnixNs(n)],
        ['apple', fromApple(n)],
        ['webkit', fromWebkit(n)],
        ['filetime', fromFiletime(n)],
    ];

    interpretationRows.innerHTML = candidates.map(([fmt, date]) => {
        const ok = !Number.isNaN(date.getTime());
        const plausible = isPlausibleDate(date);
        const value = ok ? date.toISOString() : 'ogiltigt';
        const meta = ok ? `UTC: ${date.toUTCString()}` : '';
        const tag = plausible ? ' — rimligt intervall' : '';
        return rowHtml(FORMAT_LABELS[fmt] + tag, value, meta, plausible);
    }).join('');

    interpretationsEl.classList.remove('display-none');
}

function convert() {
    const raw = rawInput.value.trim();
    if (!raw) {
        setStatus('Klistra in ett värde först', true);
        return;
    }

    let format = formatSelect.value;
    let reason = '';

    if (format === 'auto') {
        if (/[tT]|-|:|\//.test(raw) && Number.isNaN(Number(cleanNumeric(raw)))) {
            format = 'iso';
            reason = 'Indata ser ut som en datumsträng (ISO/datum).';
        } else {
            const n = parseNumber(raw);
            if (n === null) {
                const asIso = dateFromFormat('iso', raw);
                if (asIso) {
                    format = 'iso';
                    reason = 'Tolkas som datumsträng.';
                } else {
                    setStatus('Kunde inte tolka indata', true);
                    return;
                }
            } else {
                const detected = detectFormat(n, raw);
                format = detected.format;
                reason = detected.reason;
            }
        }
    }

    const date = dateFromFormat(format, raw);
    if (!date || Number.isNaN(date.getTime())) {
        setStatus('Ogiltigt värde för valt format', true);
        matrixEl.classList.add('display-none');
        return;
    }

    guessEl.textContent = `Använder: ${FORMAT_LABELS[format] || format}. ${reason}`.trim();
    guessEl.classList.remove('display-none');
    renderMatrix(date);
    renderInterpretations(raw);
    setStatus('Konvertering klar');
}

function bindCopies(root) {
    root.addEventListener('click', async (event) => {
        const btn = event.target.closest('[data-copy-id]');
        if (!btn) return;
        const el = document.getElementById(btn.dataset.copyId);
        if (!el) return;
        try {
            await navigator.clipboard.writeText(el.textContent);
            showToast();
        } catch (e) {
            setStatus('Kunde inte kopiera', true);
        }
    });
}

bindCopies(matrixRows);
bindCopies(interpretationRows);

document.getElementById('convert-button').addEventListener('click', convert);

rawInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') convert();
});

document.getElementById('now-button').addEventListener('click', () => {
    const date = new Date();
    rawInput.value = date.toISOString();
    formatSelect.value = 'iso';
    convert();
});

document.getElementById('clear-button').addEventListener('click', () => {
    rawInput.value = '';
    formatSelect.value = 'auto';
    guessEl.classList.add('display-none');
    matrixEl.classList.add('display-none');
    interpretationsEl.classList.add('display-none');
    setStatus('Klistra in ett timestamp eller datum');
});

window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    const data = event.data;
    if (data && (data.source === 'forensics-toolbox' || data.source === 'verktygslada') &&
        data.type === 'theme' && (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignoreras */ }
    }
});
