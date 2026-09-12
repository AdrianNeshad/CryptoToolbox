#!/usr/bin/env node
// Builds the Chrome (Manifest V3) extension into dist/chrome/ from the same sources
// that the Electron (.exe / .zip) build uses.
//
// The repo's existing files are NEVER modified — this script only reads them and writes
// a transformed copy into dist/chrome/. So the Electron build is completely unaffected.
//
// What it does differently from the Electron build:
//   1. Excludes CyberChef (too large + heavy WASM/eval) from the packaged extension,
//      and removes its button from the copied Toolbox.html so it doesn't 404.
//   2. Externalizes the one inline <script> in Toolbox.html into src/theme-init.js,
//      because MV3's default CSP for extension pages forbids inline scripts.
//   3. Adds manifest.json + background.js and generates PNG icons.
//   4. Registers every framed tool/doc HTML page as a sandboxed page in the manifest,
//      because the tools rely on eval() (bitcoinjs, jQuery, ...) which MV3 only allows
//      inside sandboxed pages.
//
// Run: npm run build:extension   (then load dist/chrome/ via chrome://extensions → Load unpacked)

const fs = require('node:fs');
const path = require('node:path');
const sharp = require('sharp');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'dist', 'chrome');

// Tool folders (relative to repo root, POSIX-style) to leave out of the extension build.
// Each listed folder is skipped when copying AND its sidebar button is stripped from
// the copied Toolbox.html.
const EXCLUDED_TOOLS = ['tools/CyberChef'];

// Top-level content copied verbatim (minus excluded tools) into the extension.
const COPY_DIRS = ['src', 'tools', 'documentation'];

const ICON_SIZES = [16, 32, 48, 128];

// MV3 sandbox pages run in an opaque origin (Chrome forbids `allow-same-origin` in the
// sandbox CSP), so `window.localStorage` / `sessionStorage` THROW on access. Nearly every
// tool reads localStorage during init, which would break it. This shim is injected as the
// first script of each sandboxed page: if real storage works it does nothing, otherwise it
// installs an in-memory Storage (per-session, not persisted — fine for these converters).
const STORAGE_SHIM = `<script>(function(){try{window.localStorage.getItem('__probe__');return;}catch(e){}var make=function(){var m=Object.create(null);return{getItem:function(k){k=String(k);return Object.prototype.hasOwnProperty.call(m,k)?m[k]:null;},setItem:function(k,v){m[String(k)]=String(v);},removeItem:function(k){delete m[String(k)];},clear:function(){m=Object.create(null);},key:function(i){var ks=Object.keys(m);return i>=0&&i<ks.length?ks[i]:null;},get length(){return Object.keys(m).length;}};};try{Object.defineProperty(window,'localStorage',{value:make(),configurable:true});Object.defineProperty(window,'sessionStorage',{value:make(),configurable:true});}catch(e){}})();</script>`;

function log(msg) {
    console.log(`build-extension: ${msg}`);
}

function rmrf(target) {
    fs.rmSync(target, { recursive: true, force: true });
}

// Copy a directory recursively, skipping any path that falls under an excluded tool.
function copyDir(relDir) {
    const srcDir = path.join(ROOT, relDir);
    const destDir = path.join(OUT, relDir);
    fs.cpSync(srcDir, destDir, {
        recursive: true,
        filter: (src) => {
            const rel = path.relative(ROOT, src).split(path.sep).join('/');
            return !EXCLUDED_TOOLS.some((ex) => rel === ex || rel.startsWith(ex + '/'));
        },
    });
}

// Read the version ("Version X.Y") shown in the app sidebar, mirroring scripts/sync-version.js
// so the extension version always matches the app.
function readAppVersion(html) {
    const match = html.match(/Version\s+(\d+)\.(\d+)\b/);
    if (!match) throw new Error('could not find "Version X.Y" in Toolbox.html');
    return `${match[1]}.${match[2]}.0`;
}

// Collect the data-src of every framed nav item, split into the HTML pages that must be
// sandboxed and the excluded ones (which are dropped entirely).
function collectFramedSources(html) {
    const sources = [...html.matchAll(/data-type="frame"\s+data-src="([^"]+)"/g)].map((m) => m[1]);
    const isExcluded = (src) => EXCLUDED_TOOLS.some((ex) => src === ex || src.startsWith(ex + '/'));

    const sandboxPages = sources
        .filter((src) => src.toLowerCase().endsWith('.html'))
        .filter((src) => !isExcluded(src));

    return { sandboxPages };
}

// Turn the source Toolbox.html into the extension-friendly variant. The source file on
// disk is not touched — we only transform the string we write into dist/chrome/.
function transformToolboxHtml(html) {
    // 1. Externalize the single inline (attribute-less) <script> — the theme bootstrap.
    const inlineScript = html.match(/<script>([\s\S]*?)<\/script>/);
    if (!inlineScript) throw new Error('expected an inline <script> (theme bootstrap) in Toolbox.html');
    const themeInitBody = inlineScript[1].replace(/^\n/, '').replace(/\s+$/, '') + '\n';
    fs.writeFileSync(path.join(OUT, 'src', 'theme-init.js'), themeInitBody);
    html = html.replace(inlineScript[0], '<script src="src/theme-init.js"></script>');

    // 2. Remove the sidebar button of every excluded tool so it doesn't 404 when clicked.
    for (const folder of EXCLUDED_TOOLS) {
        const escaped = folder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const buttonRe = new RegExp(
            `\\s*<button[^>]*data-src="${escaped}/[^"]*"[\\s\\S]*?</button>`,
            'g'
        );
        html = html.replace(buttonRe, '');
    }

    // 3. Point the favicon at a bundled PNG (the source uses /build/icon.ico, which the
    //    extension build does not ship).
    html = html.replace(/<link rel="icon"[^>]*>/, '<link rel="icon" type="image/png" href="icons/icon32.png">');

    return html;
}

// Insert the storage shim as the first thing inside <head> of each sandboxed page (in the
// already-copied dist files — the repo originals are never touched).
function injectStorageShim(sandboxPages) {
    let count = 0;
    for (const rel of sandboxPages) {
        const file = path.join(OUT, rel);
        let html = fs.readFileSync(file, 'utf8');
        if (html.includes('__probe__')) continue; // already injected
        const headOpen = html.match(/<head[^>]*>/i);
        if (headOpen) {
            html = html.replace(headOpen[0], headOpen[0] + '\n' + STORAGE_SHIM);
        } else {
            html = STORAGE_SHIM + '\n' + html; // no <head> — fall back to file start
        }
        fs.writeFileSync(file, html);
        count++;
    }
    log(`injected storage shim into ${count} sandboxed page(s)`);
}

async function generateIcons() {
    const svg = fs.readFileSync(path.join(ROOT, 'build', 'icon-source.svg'));
    const iconsDir = path.join(OUT, 'icons');
    fs.mkdirSync(iconsDir, { recursive: true });
    await Promise.all(
        ICON_SIZES.map((size) =>
            sharp(svg, { density: 384 })
                .resize(size, size)
                .png()
                .toFile(path.join(iconsDir, `icon${size}.png`))
        )
    );
    log(`wrote icons (${ICON_SIZES.join(', ')}px)`);
}

function writeManifest(version, sandboxPages) {
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'extension', 'manifest.json'), 'utf8'));
    manifest.version = version;
    manifest.sandbox = { pages: sandboxPages };
    fs.writeFileSync(path.join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 4) + '\n');
    log(`wrote manifest.json (version ${version}, ${sandboxPages.length} sandboxed pages)`);
}

async function main() {
    const toolboxSrc = fs.readFileSync(path.join(ROOT, 'Toolbox.html'), 'utf8');
    const version = readAppVersion(toolboxSrc);
    const { sandboxPages } = collectFramedSources(toolboxSrc);

    rmrf(OUT);
    fs.mkdirSync(OUT, { recursive: true });

    for (const dir of COPY_DIRS) copyDir(dir);
    log(`copied ${COPY_DIRS.join(', ')} (excluded: ${EXCLUDED_TOOLS.join(', ') || 'none'})`);

    injectStorageShim(sandboxPages);

    fs.writeFileSync(path.join(OUT, 'Toolbox.html'), transformToolboxHtml(toolboxSrc));
    log('wrote Toolbox.html (inline script externalized, excluded buttons removed)');

    fs.copyFileSync(path.join(ROOT, 'extension', 'background.js'), path.join(OUT, 'background.js'));

    await generateIcons();
    writeManifest(version, sandboxPages);

    log(`done → ${path.relative(ROOT, OUT)}/`);
    log('load it via chrome://extensions → enable Developer mode → Load unpacked → pick that folder');
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
