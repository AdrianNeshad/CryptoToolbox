// Removes comments from HTML, CSS and JavaScript without touching anything else.
// Used by build-standalone.js so the single-file release ships without comments.
//
// This is not a minifier: code, strings, whitespace and line breaks are kept as they are.
// Only comments go, plus the whitespace a comment leaves behind (a line that held nothing
// but a comment is dropped, and the spaces before a trailing comment are trimmed).
//
// - JavaScript: a small tokenizer that tracks strings, template literals (with nested
//   ${...}), regex literals and comments, so "//" or "/*" inside a string or regex is
//   never mistaken for a comment. A multi-line template literal without ${...} that is
//   itself JavaScript (worker source built as a string) is stripped as well. Every stripped script is compiled with node:vm, and the
//   build fails if a script that compiled before no longer does.
// - CSS: /* ... */ outside strings.
// - HTML: <!-- ... --> in markup, and the contents of <script> (JavaScript types only)
//   and <style>. Raw text elements (<textarea>, <title>, ...) and non-JS scripts
//   (application/json, text/template, ...) are left untouched.

const vm = require('node:vm');

const compiles = (code) => {
    try { new vm.Script(code); return true; } catch { return false; }
};
const isNL = (c) => c === '\n' || c === '\r' || c === '\u2028' || c === '\u2029';
const isWs = (c) => c === ' ' || c === '\t' || c === '\f' || c === '\v' || c === '\u00a0' || c === '\ufeff';
const isIdent = (c) => c !== undefined && (/[A-Za-z0-9_$]/.test(c) || c.charCodeAt(0) > 127);

// Output buffer that knows how to tidy up the line a comment was removed from.
class Out {
    constructor() { this.parts = []; this.blank = true; }
    push(s) {
        if (!s) return;
        this.parts.push(s);
        for (let k = s.length - 1; k >= 0; k--) {
            if (isNL(s[k])) { this.blank = true; return; }
            if (!isWs(s[k])) { this.blank = false; return; }
        }
    }
    // True when the current output line holds only whitespace so far.
    lineIsBlank() { return this.blank; }
    trimTrailingWs() {
        while (this.parts.length) {
            const s = this.parts[this.parts.length - 1];
            let k = s.length;
            while (k > 0 && isWs(s[k - 1])) k--;
            if (k === 0) { this.parts.pop(); continue; }
            this.parts[this.parts.length - 1] = s.slice(0, k);
            break;
        }
        const last = this.lastChar();
        this.blank = last === undefined || isNL(last);
    }
    lastChar() {
        for (let p = this.parts.length - 1; p >= 0; p--) {
            if (this.parts[p].length) return this.parts[p][this.parts[p].length - 1];
        }
        return undefined;
    }
    toString() { return this.parts.join(''); }
}

// Drop the comment src[start, end) and tidy the surrounding whitespace. `needsGap(prev,
// next)` says whether a space must stay between the code on each side. Returns the index
// to continue scanning from.
function removeComment(src, out, start, end, needsGap) {
    const n = src.length;
    const comment = src.slice(start, end);
    const hasNL = /[\n\r\u2028\u2029]/.test(comment);
    let j = end;
    while (j < n && isWs(src[j])) j++;
    const afterBlank = j >= n || isNL(src[j]);
    const beforeBlank = out.lineIsBlank();

    if (afterBlank) {
        out.trimTrailingWs();
        if (beforeBlank && j < n) {
            // The line held only the comment: drop the line break too.
            j += src[j] === '\r' && src[j + 1] === '\n' ? 2 : 1;
        } else if (beforeBlank && j >= n) {
            // Comment on the last line: also drop the line break before it.
            const last = out.parts.length - 1;
            if (last >= 0) out.parts[last] = out.parts[last].replace(/\r?\n$/, '');
            out.blank = false;
        }
        return j;
    }
    if (beforeBlank) return j; // comment, then code on the same line: keep the indentation
    if (hasNL) { out.push('\n'); return j; } // a line break may matter (ASI)
    const prev = out.lastChar();
    if (isWs(prev) || isWs(src[end])) return end;
    if (needsGap(prev, src[end])) out.push(' ');
    return end;
}

const REGEX_AFTER_WORD = new Set([
    'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw',
    'case', 'do', 'else', 'yield', 'await',
]);

function stripJs(src) {
    const out = new Out();
    const n = src.length;
    const stack = []; // '{' for a block/object brace, '${' for a template substitution
    let i = 0;
    let seg = 0;
    // What the last significant token was, to tell a regex literal from a division.
    let regexOk = true;

    const flush = (to) => { out.push(src.slice(seg, to)); };

    // Scan a template literal body starting right after ` (or after the } closing a ${).
    const scanTemplate = () => {
        while (i < n) {
            const c = src[i];
            if (c === '\\') { i += 2; continue; }
            if (c === '`') { i++; regexOk = false; return; }
            if (c === '$' && src[i + 1] === '{') { i += 2; stack.push('${'); regexOk = true; return; }
            i++;
        }
    };

    while (i < n) {
        const c = src[i];
        const d = src[i + 1];

        if (c === '/' && d === '/') {
            let e = i + 2;
            while (e < n && !isNL(src[e])) e++;
            flush(i);
            i = seg = removeComment(src, out, i, e, (a, b) => isIdent(a) && isIdent(b) || a === b);
            continue;
        }
        if (c === '/' && d === '*') {
            const close = src.indexOf('*/', i + 2);
            const e = close < 0 ? n : close + 2;
            flush(i);
            i = seg = removeComment(src, out, i, e, (a, b) => isIdent(a) && isIdent(b) || a === b);
            continue;
        }
        if (c === '"' || c === "'") {
            i++;
            while (i < n && src[i] !== c && !isNL(src[i])) i += src[i] === '\\' ? 2 : 1;
            i++;
            regexOk = false;
            continue;
        }
        if (c === '`') {
            const start = i;
            const depth = stack.length;
            i++;
            scanTemplate();
            // A plain multi-line template that is itself JavaScript (e.g. worker source
            // passed to a Blob) gets its comments stripped too, but only when it compiles
            // both before and after.
            if (stack.length === depth && src[i - 1] === '`') {
                const body = src.slice(start + 1, i - 1);
                if (/[\n\r]/.test(body) && /\/[/*]/.test(body) && compiles(body)) {
                    const stripped = stripJs(body);
                    if (stripped !== body && compiles(stripped)) {
                        flush(start + 1);
                        out.push(stripped);
                        seg = i - 1;
                    }
                }
            }
            continue;
        }
        if (c === '/') {
            if (regexOk) {
                i++;
                let inClass = false;
                while (i < n && !isNL(src[i])) {
                    const r = src[i];
                    if (r === '\\') { i += 2; continue; }
                    if (r === '[') inClass = true;
                    else if (r === ']') inClass = false;
                    else if (r === '/' && !inClass) break;
                    i++;
                }
                i++;
                while (i < n && isIdent(src[i])) i++; // flags
                regexOk = false;
            } else {
                i++;
                regexOk = true;
            }
            continue;
        }
        if (c === '{') { stack.push('{'); i++; regexOk = true; continue; }
        if (c === '}') {
            const top = stack.pop();
            i++;
            if (top === '${') scanTemplate();
            else regexOk = true;
            continue;
        }
        if (isIdent(c) || (c === '.' && /[0-9]/.test(d || ''))) {
            const s = i;
            const isNum = /[0-9.]/.test(c);
            i++;
            while (i < n && (isIdent(src[i]) || (isNum && src[i] === '.'))) i++;
            const word = src.slice(s, i);
            const prevDot = s > 0 && src[s - 1] === '.' && src[s - 2] !== '.';
            regexOk = !prevDot && REGEX_AFTER_WORD.has(word);
            continue;
        }
        if (isWs(c) || isNL(c)) { i++; continue; }
        // Punctuation: a regex may follow anything except a closing ) or ], or ++/--.
        if (c === ')' || c === ']') regexOk = false;
        else if ((c === '+' || c === '-') && d === c) { i += 2; regexOk = false; continue; }
        else regexOk = true;
        i++;
    }
    flush(n);
    return out.toString();
}

function stripCss(src) {
    const out = new Out();
    const n = src.length;
    let i = 0;
    let seg = 0;
    while (i < n) {
        const c = src[i];
        if (c === '"' || c === "'") {
            i++;
            while (i < n && src[i] !== c && !isNL(src[i])) i += src[i] === '\\' ? 2 : 1;
            i++;
            continue;
        }
        if (c === '/' && src[i + 1] === '*') {
            const close = src.indexOf('*/', i + 2);
            const e = close < 0 ? n : close + 2;
            out.push(src.slice(seg, i));
            i = seg = removeComment(src, out, i, e,
                (a, b) => /[\w-]/.test(a || '') && /[\w-]/.test(b || ''));
            continue;
        }
        i++;
    }
    out.push(src.slice(seg));
    return out.toString();
}

const JS_TYPES = new Set([
    '', 'text/javascript', 'application/javascript', 'application/ecmascript',
    'text/ecmascript', 'module', 'application/x-javascript', 'text/x-javascript',
]);
const RAW_TEXT = new Set(['textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext']);

function attr(tag, name) {
    const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
    return m ? (m[2] ?? m[3] ?? m[4]) : null;
}

// Throws when stripping turned a script that compiled into one that doesn't.
function checkJs(before, after, where) {
    if (compiles(before) && !compiles(after)) {
        let detail = '';
        try { new vm.Script(after); } catch (e) { detail = e.message; }
        throw new Error(`stripping comments broke a script in ${where}: ${detail}`);
    }
}

function stripHtml(src, where = 'document', stats = { scripts: 0, styles: 0 }) {
    const out = new Out();
    const n = src.length;
    let i = 0;
    let seg = 0;
    while (i < n) {
        const lt = src.indexOf('<', i);
        if (lt < 0) break;
        i = lt;

        if (src.startsWith('<!--', i)) {
            const close = src.indexOf('-->', i + 4);
            const e = close < 0 ? n : close + 3;
            out.push(src.slice(seg, i));
            i = seg = removeComment(src, out, i, e, () => false);
            continue;
        }

        const m = /^<([A-Za-z][A-Za-z0-9-]*)/.exec(src.slice(i, i + 64));
        if (!m) { i++; continue; }

        // Find the end of the start tag, skipping quoted attribute values.
        let k = i + m[0].length;
        let q = null;
        while (k < n) {
            const ch = src[k];
            if (q) { if (ch === q) q = null; } else if (ch === '"' || ch === "'") q = ch; else if (ch === '>') break;
            k++;
        }
        const tagEnd = k + 1;
        const name = m[1].toLowerCase();
        i = tagEnd;

        if (name !== 'script' && name !== 'style' && !RAW_TEXT.has(name)) continue;

        const closeRe = new RegExp(`</${name}[\\s/>]`, 'ig');
        closeRe.lastIndex = tagEnd;
        const cm = closeRe.exec(src);
        const bodyEnd = cm ? cm.index : n;
        const body = src.slice(tagEnd, bodyEnd);
        const tag = src.slice(lt, tagEnd);

        let replaced = null;
        if (name === 'style') {
            replaced = stripCss(body);
            stats.styles++;
        } else if (name === 'script') {
            const type = (attr(tag, 'type') || '').trim().toLowerCase().split(';')[0].trim();
            if (JS_TYPES.has(type) && !attr(tag, 'src')) {
                replaced = stripJs(body);
                if (type !== 'module') checkJs(body, replaced, where);
                stats.scripts++;
            }
        }
        if (replaced !== null) {
            out.push(src.slice(seg, tagEnd));
            out.push(replaced);
            seg = bodyEnd;
        }
        i = bodyEnd;
    }
    out.push(src.slice(seg));
    return out.toString();
}

module.exports = { stripJs, stripCss, stripHtml };
