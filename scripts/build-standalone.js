#!/usr/bin/env node
// Produces a single, self-contained HTML file of the whole toolbox (CyberChef excluded)
// into release/:
//
//   CryptoToolbox-<ver>.html
//        Everything baked into one file: the Toolbox shell (style.css + script.js), every
//        tool in the sidebar with all of its local stylesheets and scripts, and the
//        documentation pages and PDFs. CyberChef (~75 MB, 134 files, wasm) is left out and
//        its sidebar entry is hidden in this version.
//
// Why: some managed Windows machines (Edge with the IntranetFileLinksEnabled policy) block
// every file:// navigation a page starts itself, so the normal version can't show its tools
// in iframes there. This file never navigates to file://: each tool is stored in the page as
// a string and shown in a sandboxed srcdoc iframe when it is opened (see the standalone
// branch in src/script.js).
//
// The source code is not changed: this script only reads Toolbox.html, src/ and the tool
// folders. The version is read from "Version X.Y" in Toolbox.html (the same text shown in
// the app sidebar), so the file name always follows the app version.
//
// Run: node scripts/build-standalone.js   (or: npm run build:standalone)

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const RELEASE_DIR = path.join(ROOT, 'release');
const TOOLBOX_HTML = path.join(ROOT, 'Toolbox.html');

// Sidebar entries that are not baked in (their entries are hidden in the standalone file).
const EXCLUDE = [/^tools\/CyberChef\//i];

function log(msg) {
    console.log(`build-standalone: ${msg}`);
}

function readShortVersion(html) {
    const match = html.match(/Version\s+(\d+)\.(\d+)\b/);
    if (!match) throw new Error('could not find "Version X.Y" in Toolbox.html');
    return `${match[1]}.${match[2]}`;
}

function readText(file) {
    return fs.readFileSync(file, 'utf8');
}

// Text that ends up inside an inline <script> must not close it early.
function escapeInlineScript(code) {
    return code.replace(/<\/script/gi, '<\\/script');
}

// Text that ends up inside an inline <style> must not close it early.
function escapeInlineStyle(css) {
    return css.replace(/<\/style/gi, '<\\/style');
}

function isLocalRef(ref) {
    return ref && !/^(?:[a-z][a-z0-9+.-]*:|\/\/|\/|#)/i.test(ref);
}

// Resolve a reference from an HTML file the way a browser would (relative to that file),
// on disk. Returns null when it doesn't point to an existing file in the repo.
function resolveRef(htmlFile, ref) {
    const clean = decodeURIComponent(ref.split(/[?#]/)[0]);
    const file = path.resolve(path.dirname(htmlFile), clean);
    if (!file.startsWith(ROOT + path.sep)) return null;
    return fs.existsSync(file) && fs.statSync(file).isFile() ? file : null;
}

function getAttr(tag, name) {
    const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
    return m ? (m[2] ?? m[3] ?? m[4]) : null;
}

// Inline every local <link rel="stylesheet" href> and <script src></script> of an HTML
// document, so that it no longer loads anything from disk.
function inlineDocument(htmlFile, stats) {
    let html = readText(htmlFile);

    // In the standalone file the theme can't be passed as ?theme= (srcdoc pages have no query
    // string) and localStorage is unavailable in the sandbox, so the shell replaces this
    // placeholder with the current theme when it opens the tool. Placed last in <head> so it
    // wins over the tool's own theme script. Done before inlining, so a "</head>" inside an
    // inlined library can never be mistaken for the real one.
    const themeScript =
        '<script>(function(){var t="__CRYPTOTOOLBOX_THEME__";' +
        'if(t==="light"||t==="dark")document.documentElement.setAttribute("data-theme",t);})();</script>';
    if (/<\/head>/i.test(html)) {
        html = html.replace(/<\/head>/i, () => `${themeScript}\n</head>`);
    } else {
        html = themeScript + html;
    }

    html = html.replace(/<link\b[^>]*>/gi, (tag) => {
        const rel = (getAttr(tag, 'rel') || '').toLowerCase();
        const href = getAttr(tag, 'href');
        if (rel !== 'stylesheet' || !isLocalRef(href)) return tag;
        const file = resolveRef(htmlFile, href);
        if (!file) {
            stats.missing.push(`${path.relative(ROOT, htmlFile)} -> ${href}`);
            return tag;
        }
        stats.inlined++;
        return `<style>\n${escapeInlineStyle(readText(file))}\n</style>`;
    });

    html = html.replace(/<script\b([^>]*)>\s*<\/script>/gi, (tag, attrs) => {
        const src = getAttr(`<script ${attrs}>`, 'src');
        if (!isLocalRef(src)) return tag;
        const file = resolveRef(htmlFile, src);
        if (!file) {
            stats.missing.push(`${path.relative(ROOT, htmlFile)} -> ${src}`);
            return tag;
        }
        stats.inlined++;
        // Keep any other attributes (type, charset, …) but drop src/defer/async.
        const keep = attrs.replace(/\s(?:src|defer|async)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/gi, '');
        return `<script${keep}>\n${escapeInlineScript(readText(file))}\n</script>`;
    });

    return html;
}

// JSON inside <script type="application/json">: escaping "<" keeps the HTML parser from
// ever seeing "</script" (or "<!--") in the data.
function jsonForScriptTag(value) {
    return JSON.stringify(value)
        .replace(/</g, "\\u003c")
        .replace(new RegExp("\\u2028", "g"), "\\u2028")
        .replace(new RegExp("\\u2029", "g"), "\\u2029");
}

function escapeAttr(value) {
    return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

function cleanOldStandalone(keep) {
    if (!fs.existsSync(RELEASE_DIR)) return;
    for (const file of fs.readdirSync(RELEASE_DIR)) {
        if (/^CryptoToolbox-\d+\.\d+\.html$/.test(file) && file !== keep) {
            fs.unlinkSync(path.join(RELEASE_DIR, file));
            log(`removed stale ${file}`);
        }
    }
}

function main() {
    let shell = readText(TOOLBOX_HTML);
    const version = readShortVersion(shell);
    const outName = `CryptoToolbox-${version}.html`;
    const stats = { inlined: 0, missing: [] };

    // 1. The shell's own stylesheet and script.
    shell = shell.replace(/<link\b[^>]*href="src\/style\.css"[^>]*>/i,
        () => `<style>\n${escapeInlineStyle(readText(path.join(ROOT, 'src', 'style.css')))}\n</style>`);
    shell = shell.replace(/<script\s+src="src\/script\.js"><\/script>/i,
        () => '<script>window.CRYPTOTOOLBOX_STANDALONE = true;</script>\n' +
            `<script>\n${escapeInlineScript(readText(path.join(ROOT, 'src', 'script.js')))}\n</script>`);
    if (/src="src\/script\.js"|href="src\/style\.css"/.test(shell)) {
        throw new Error('could not inline src/style.css or src/script.js into the shell');
    }

    // 2. Every sidebar entry (tools + documentation), each stored as its own JSON block.
    const sources = [...new Set([...shell.matchAll(/data-src="([^"]+)"/g)].map((m) => m[1]))];
    const blocks = [];
    let included = 0;
    for (const src of sources) {
        const rel = src.split(/[?#]/)[0];
        if (EXCLUDE.some((re) => re.test(rel))) {
            log(`skipped ${rel} (excluded from the standalone file)`);
            continue;
        }
        const file = resolveRef(TOOLBOX_HTML, rel);
        if (!file) throw new Error(`sidebar entry ${src} does not exist on disk`);

        let entry;
        if (/\.pdf$/i.test(file)) {
            entry = { kind: 'pdf', data: fs.readFileSync(file).toString('base64') };
        } else if (/\.html?$/i.test(file)) {
            entry = { kind: 'html', data: inlineDocument(file, stats) };
        } else {
            throw new Error(`don't know how to bake in ${src}`);
        }
        blocks.push(`<script type="application/json" data-standalone-src="${escapeAttr(src)}">` +
            `${jsonForScriptTag(entry)}</script>`);
        included++;
    }

    if (stats.missing.length) {
        throw new Error('local files referenced by a tool were not found:\n  ' + stats.missing.join('\n  '));
    }

    // 3. The data blocks go right before the shell's scripts, so they are all in the DOM when
    //    script.js runs (it removes sidebar entries that have no block, e.g. CyberChef).
    const marker = '<script>window.CRYPTOTOOLBOX_STANDALONE = true;</script>';
    if (shell.split(marker).length !== 2) throw new Error('standalone marker not found exactly once');
    const out = shell.replace(marker, () => `${blocks.join('\n')}\n${marker}`);

    fs.mkdirSync(RELEASE_DIR, { recursive: true });
    cleanOldStandalone(outName);
    fs.writeFileSync(path.join(RELEASE_DIR, outName), out);

    const mb = (Buffer.byteLength(out) / (1024 * 1024)).toFixed(1);
    log(`wrote release/${outName} (${mb} MB, ${included} entries, ${stats.inlined} files inlined)`);
}

main();
