#!/usr/bin/env node
// Renames the files electron-builder just built in release/ to their final,
// user-facing name: "CryptoToolboxX.Y.exe" (portable) and
// "CryptoToolboxX.Y-Installer.exe" (NSIS installer) — where X.Y is always the same
// version shown in Toolbox.html's sidebar.
//
// Note: GitHub Releases automatically sanitizes asset filenames on upload (å/ä/ö -> a/a/o,
// space -> dot). We therefore use a hyphen instead of a space here, so the
// sanitized result becomes "CryptoToolbox1.6-Installer.exe" and not "...1.6.Installer.exe".
//
// Runs automatically after `npm run dist` / `dist:portable` / `dist:installer`.

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const RELEASE_DIR = path.join(ROOT, 'release');

const html = fs.readFileSync(path.join(ROOT, 'Toolbox.html'), 'utf8');
const match = html.match(/Version\s+(\d+)\.(\d+)\b/);
if (!match) {
    console.error('finalize-artifacts: could not find "Version X.Y" in Toolbox.html');
    process.exit(1);
}
const shortVersion = `${match[1]}.${match[2]}`;

if (!fs.existsSync(RELEASE_DIR)) {
    console.error(`finalize-artifacts: cannot find the build folder ${RELEASE_DIR}`);
    process.exit(1);
}

const portableName = `CryptoToolbox${shortVersion}.exe`;
const installerName = `CryptoToolbox${shortVersion}-Installer.exe`;

// Clean up any previously renamed files from local test builds of another version,
// so they don't linger and cause confusion next to the new build.
for (const file of fs.readdirSync(RELEASE_DIR)) {
    if (/^CryptoToolbox\d+\.\d+(-Installer)?\.exe$/.test(file) && file !== portableName && file !== installerName) {
        fs.unlinkSync(path.join(RELEASE_DIR, file));
    }
}

function renameFirstMatch(pattern, targetName) {
    const files = fs.readdirSync(RELEASE_DIR);
    const found = files.find((f) => pattern.test(f));
    if (!found) {
        console.warn(`finalize-artifacts: found no file matching ${pattern} in release/ — skipping.`);
        return;
    }
    const from = path.join(RELEASE_DIR, found);
    const to = path.join(RELEASE_DIR, targetName);
    if (from !== to) {
        fs.renameSync(from, to);
    }
    console.log(`finalize-artifacts: ${found} -> ${targetName}`);
}

renameFirstMatch(/^CryptoToolbox-Portable-.*\.exe$/i, portableName);
renameFirstMatch(/^CryptoToolbox Setup .*\.exe$/i, installerName);
