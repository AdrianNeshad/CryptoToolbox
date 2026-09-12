#!/usr/bin/env node
// Produces the two extra release artifacts (next to the Electron .exe) into release/:
//
//   1. CryptoToolbox<ver>-Chrome-Extension.zip
//        The Manifest V3 extension (dist/chrome), zipped with manifest.json at the ROOT
//        of the archive — ready to drag into the Chrome Web Store, or to unzip and load
//        via chrome://extensions → Load unpacked. CyberChef is excluded (see build-extension.js).
//
//   2. CryptoToolbox<ver>.zip
//        The plain browser version for running locally: only the files needed to open the
//        toolbox in a browser (Toolbox.html, src/, tools/ — CyberChef included here —,
//        documentation/, LICENSE). The Electron wrapper, the extension packaging, the build
//        scripts and all other repo/dev files are left out. Unzips into a single
//        CryptoToolbox<ver>/ folder; open its Toolbox.html (a local web server is the most
//        reliable way, e.g. `python3 -m http.server`).
//
// Runs the extension build first so dist/chrome is always fresh. Zips with the OS zip tool
// (no extra npm dependency): PowerShell Compress-Archive on Windows (the CI runner), `zip`
// elsewhere.
//
// Run: node scripts/build-release-zips.js   (or: npm run build:zips)

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const RELEASE_DIR = path.join(ROOT, 'release');
const DIST_CHROME = path.join(ROOT, 'dist', 'chrome');
const DIST_LOCAL = path.join(ROOT, 'dist', 'local');

// Files/folders that make up the "run locally in a browser" bundle. Everything else in the
// repo (electron/, extension/, scripts/, build/, node_modules/, dist/, .github/, config...) is
// intentionally left out because it is not needed to run the toolbox.
const LOCAL_INCLUDE = ['Toolbox.html', 'src', 'tools', 'documentation', 'LICENSE'];

function log(msg) {
    console.log(`build-release-zips: ${msg}`);
}

function readShortVersion() {
    const html = fs.readFileSync(path.join(ROOT, 'Toolbox.html'), 'utf8');
    const match = html.match(/Version\s+(\d+)\.(\d+)\b/);
    if (!match) throw new Error('could not find "Version X.Y" in Toolbox.html');
    return `${match[1]}.${match[2]}`;
}

// Zip the CONTENTS of srcDir so that its top-level entries sit at the archive root.
function zipContents(srcDir, zipPath) {
    fs.rmSync(zipPath, { force: true });
    if (process.platform === 'win32') {
        const cmd = `Compress-Archive -Path '${srcDir}${path.sep}*' -DestinationPath '${zipPath}' -Force`;
        execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', cmd], { stdio: 'inherit' });
    } else {
        execFileSync('zip', ['-r', '-q', '-X', zipPath, '.'], { cwd: srcDir, stdio: 'inherit' });
    }
}

// Zip a single folder (parentDir/folderName) so the archive contains that folder at its root.
function zipFolder(parentDir, folderName, zipPath) {
    fs.rmSync(zipPath, { force: true });
    if (process.platform === 'win32') {
        const cmd = `Compress-Archive -Path '${path.join(parentDir, folderName)}' -DestinationPath '${zipPath}' -Force`;
        execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', cmd], { stdio: 'inherit' });
    } else {
        execFileSync('zip', ['-r', '-q', '-X', zipPath, folderName], { cwd: parentDir, stdio: 'inherit' });
    }
}

// Remove stale zips from earlier/other versions so release/ only holds the current ones.
function cleanOldZips(keep) {
    if (!fs.existsSync(RELEASE_DIR)) return;
    for (const file of fs.readdirSync(RELEASE_DIR)) {
        if (/^CryptoToolbox\d+\.\d+(-Chrome-Extension)?\.zip$/.test(file) && !keep.includes(file)) {
            fs.unlinkSync(path.join(RELEASE_DIR, file));
            log(`removed stale ${file}`);
        }
    }
}

function main() {
    const version = readShortVersion();

    // 1. Fresh extension build (dist/chrome).
    execFileSync('node', [path.join('scripts', 'build-extension.js')], { cwd: ROOT, stdio: 'inherit' });

    fs.mkdirSync(RELEASE_DIR, { recursive: true });

    const chromeZipName = `CryptoToolbox${version}-Chrome-Extension.zip`;
    const localZipName = `CryptoToolbox${version}.zip`;
    cleanOldZips([chromeZipName, localZipName]);

    // 2. Chrome extension zip (manifest.json at archive root).
    zipContents(DIST_CHROME, path.join(RELEASE_DIR, chromeZipName));
    log(`wrote release/${chromeZipName}`);

    // 3. Local browser bundle → staged into dist/local/CryptoToolbox<ver>/ then zipped.
    fs.rmSync(DIST_LOCAL, { recursive: true, force: true });
    const stageName = `CryptoToolbox${version}`;
    const stageDir = path.join(DIST_LOCAL, stageName);
    fs.mkdirSync(stageDir, { recursive: true });
    for (const item of LOCAL_INCLUDE) {
        const from = path.join(ROOT, item);
        if (!fs.existsSync(from)) {
            log(`WARNING: ${item} not found — skipping`);
            continue;
        }
        fs.cpSync(from, path.join(stageDir, item), { recursive: true });
    }
    zipFolder(DIST_LOCAL, stageName, path.join(RELEASE_DIR, localZipName));
    log(`wrote release/${localZipName} (contents: ${LOCAL_INCLUDE.join(', ')})`);

    log('done');
}

main();
