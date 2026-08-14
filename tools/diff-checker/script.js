const inputA = document.getElementById('input-a');
const inputB = document.getElementById('input-b');
const clearButton = document.getElementById('clear-button');
const optIgnoreCase = document.getElementById('opt-ignore-case');
const optIgnoreWhitespace = document.getElementById('opt-ignore-whitespace');
const statusEl = document.getElementById('status');
const resultEl = document.getElementById('result');
const statsEl = document.getElementById('stats');
const diffOutput = document.getElementById('diff-output');

// Över denna gräns (rader_A × rader_B) skippas LCS och allt markeras som utbytt.
const MAX_LCS_CELLS = 4_000_000;

function setStatus(msg, isError) {
    statusEl.textContent = msg;
    statusEl.style.color = isError ? 'var(--error)' : 'var(--text-muted)';
}

function normalizeLine(line) {
    let out = line;
    if (optIgnoreWhitespace.checked) out = out.trim();
    if (optIgnoreCase.checked) out = out.toLowerCase();
    return out;
}

/**
 * Rad-diff via LCS med trimning av gemensam början/slut.
 * Returnerar ops: { type: 'equal' | 'del' | 'ins', a?: index, b?: index }
 */
function computeDiff(aLines, bLines) {
    let start = 0;
    while (start < aLines.length && start < bLines.length && aLines[start] === bLines[start]) {
        start++;
    }
    let endA = aLines.length;
    let endB = bLines.length;
    while (endA > start && endB > start && aLines[endA - 1] === bLines[endB - 1]) {
        endA--;
        endB--;
    }

    const ops = [];
    for (let i = 0; i < start; i++) ops.push({ type: 'equal', a: i, b: i });
    ops.push(...lcsDiff(aLines, bLines, start, endA, start, endB));
    for (let i = 0; endA + i < aLines.length; i++) {
        ops.push({ type: 'equal', a: endA + i, b: endB + i });
    }
    return ops;
}

function lcsDiff(aLines, bLines, aStart, aEnd, bStart, bEnd) {
    const n = aEnd - aStart;
    const m = bEnd - bStart;
    const ops = [];

    if (n === 0 && m === 0) return ops;
    if (n === 0 || m === 0 || n * m > MAX_LCS_CELLS) {
        for (let i = 0; i < n; i++) ops.push({ type: 'del', a: aStart + i });
        for (let j = 0; j < m; j++) ops.push({ type: 'ins', b: bStart + j });
        return ops;
    }

    // DP-tabell över LCS-längder, (n+1) × (m+1)
    const width = m + 1;
    const table = new Uint32Array((n + 1) * width);
    for (let i = 1; i <= n; i++) {
        for (let j = 1; j <= m; j++) {
            if (aLines[aStart + i - 1] === bLines[bStart + j - 1]) {
                table[i * width + j] = table[(i - 1) * width + (j - 1)] + 1;
            } else {
                const up = table[(i - 1) * width + j];
                const left = table[i * width + (j - 1)];
                table[i * width + j] = up > left ? up : left;
            }
        }
    }

    // Backtracka och bygg ops baklänges
    let i = n;
    let j = m;
    const reversed = [];
    while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && aLines[aStart + i - 1] === bLines[bStart + j - 1]) {
            reversed.push({ type: 'equal', a: aStart + i - 1, b: bStart + j - 1 });
            i--;
            j--;
        } else if (j > 0 && (i === 0 || table[i * width + (j - 1)] >= table[(i - 1) * width + j])) {
            reversed.push({ type: 'ins', b: bStart + j - 1 });
            j--;
        } else {
            reversed.push({ type: 'del', a: aStart + i - 1 });
            i--;
        }
    }
    reversed.reverse();
    ops.push(...reversed);
    return ops;
}

/** Gemensam prefix/suffix mellan två strängar → intervall som skiljer sig. */
function inlineHighlightRange(a, b) {
    let prefix = 0;
    while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++;
    let suffix = 0;
    while (
        suffix < a.length - prefix &&
        suffix < b.length - prefix &&
        a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
    ) {
        suffix++;
    }
    return {
        aStart: prefix, aEnd: a.length - suffix,
        bStart: prefix, bEnd: b.length - suffix,
    };
}

function makeLineText(text, extraClass, hlStart, hlEnd, hlClass) {
    const cell = document.createElement('div');
    cell.className = 'line-text' + (extraClass ? ' ' + extraClass : '');
    if (hlClass != null && hlEnd > hlStart) {
        cell.append(document.createTextNode(text.slice(0, hlStart)));
        const mark = document.createElement('span');
        mark.className = hlClass;
        mark.textContent = text.slice(hlStart, hlEnd);
        cell.append(mark);
        cell.append(document.createTextNode(text.slice(hlEnd)));
    } else {
        cell.textContent = text;
    }
    return cell;
}

function makeLineNum(num) {
    const cell = document.createElement('div');
    cell.className = 'line-num';
    cell.textContent = num == null ? '' : String(num);
    return cell;
}

function appendRow(fragment, aNum, aCell, bNum, bCell) {
    const row = document.createElement('div');
    row.className = 'diff-row';
    row.append(makeLineNum(aNum), aCell, makeLineNum(bNum), bCell);
    fragment.append(row);
}

function emptyCell() {
    return makeLineText('', 'line-text--empty');
}

function renderDiff(ops, aLines, bLines) {
    const fragment = document.createDocumentFragment();
    let k = 0;
    while (k < ops.length) {
        const op = ops[k];
        if (op.type === 'equal') {
            appendRow(fragment,
                op.a + 1, makeLineText(aLines[op.a]),
                op.b + 1, makeLineText(bLines[op.b]));
            k++;
            continue;
        }

        // Samla ihop en sammanhängande grupp av del/ins och para ihop dem
        const dels = [];
        const inss = [];
        while (k < ops.length && ops[k].type !== 'equal') {
            if (ops[k].type === 'del') dels.push(ops[k]);
            else inss.push(ops[k]);
            k++;
        }
        const pairs = Math.max(dels.length, inss.length);
        for (let p = 0; p < pairs; p++) {
            const del = dels[p];
            const ins = inss[p];
            let aCell = emptyCell();
            let bCell = emptyCell();
            let aNum = null;
            let bNum = null;
            if (del && ins) {
                const range = inlineHighlightRange(aLines[del.a], bLines[ins.b]);
                aCell = makeLineText(aLines[del.a], 'line-text--del', range.aStart, range.aEnd, 'ihl-del');
                bCell = makeLineText(bLines[ins.b], 'line-text--ins', range.bStart, range.bEnd, 'ihl-ins');
                aNum = del.a + 1;
                bNum = ins.b + 1;
            } else if (del) {
                aCell = makeLineText(aLines[del.a], 'line-text--del');
                aNum = del.a + 1;
            } else {
                bCell = makeLineText(bLines[ins.b], 'line-text--ins');
                bNum = ins.b + 1;
            }
            appendRow(fragment, aNum, aCell, bNum, bCell);
        }
    }
    diffOutput.replaceChildren(fragment);
}

function compare() {
    const textA = inputA.value;
    const textB = inputB.value;

    if (textA === '' && textB === '') {
        resultEl.classList.add('display-none');
        diffOutput.replaceChildren();
        setStatus('Klistra in två texter — skillnaderna visas automatiskt');
        return;
    }

    const aLines = textA.split('\n');
    const bLines = textB.split('\n');
    const aNorm = aLines.map(normalizeLine);
    const bNorm = bLines.map(normalizeLine);

    const ops = computeDiff(aNorm, bNorm);
    const added = ops.filter(op => op.type === 'ins').length;
    const removed = ops.filter(op => op.type === 'del').length;
    const unchanged = ops.filter(op => op.type === 'equal').length;

    renderDiff(ops, aLines, bLines);
    resultEl.classList.remove('display-none');

    if (added === 0 && removed === 0) {
        setStatus('Texterna är identiska' +
            (optIgnoreCase.checked || optIgnoreWhitespace.checked ? ' (med valda inställningar)' : ''));
        statsEl.textContent = `(${unchanged} rader)`;
    } else {
        setStatus('Skillnader hittades');
        statsEl.textContent = `(+${added} tillagda · −${removed} borttagna · ${unchanged} oförändrade rader)`;
    }
}

// Kort debounce så snabb inmatning i stora texter inte kör diffen för varje tangent
let debounceTimer = null;
function scheduleCompare() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(compare, 150);
}

inputA.addEventListener('input', scheduleCompare);
inputB.addEventListener('input', scheduleCompare);
optIgnoreCase.addEventListener('change', compare);
optIgnoreWhitespace.addEventListener('change', compare);

clearButton.addEventListener('click', () => {
    clearTimeout(debounceTimer);
    inputA.value = '';
    inputB.value = '';
    diffOutput.replaceChildren();
    resultEl.classList.add('display-none');
    setStatus('Klistra in två texter — skillnaderna visas automatiskt');
    inputA.focus();
});

window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    const data = event.data;
    if (data && data.source === 'verktygslada' &&
        data.type === 'theme' && (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignoreras */ }
    }
});
