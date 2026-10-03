#!/usr/bin/env node
// Produces the local browser release artifact (next to the Electron .exe) into release/:
//
//   CryptoToolbox<ver>.zip
//        The plain browser version for running locally: only the files needed to open the
//        toolbox in a browser (Toolbox.html, src/, tools/ — CyberChef included —,
//        documentation/). The Electron wrapper, the build scripts and all other repo/dev
//        files are left out. Unzips into a single CryptoToolbox<ver>/ folder; open its
//        Toolbox.html (a local web server is the most reliable way, e.g.
//        `python3 -m http.server`).
//
// Zips with the OS zip tool (no extra npm dependency): PowerShell Compress-Archive on
// Windows (the CI runner), `zip` elsewhere.
//
// Run: node scripts/build-release-zips.js   (or: npm run build:zips)

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const RELEASE_DIR = path.join(ROOT, 'release');
const DIST_LOCAL = path.join(ROOT, 'dist', 'local');

// Files/folders that make up the "run locally in a browser" bundle. Everything else in the
// repo (electron/, scripts/, build/, node_modules/, dist/, .github/, config...) is
// intentionally left out because it is not needed to run the toolbox.
const LOCAL_INCLUDE = ['Toolbox.html', 'src', 'tools', 'documentation'];

function log(msg) {
    console.log(`build-release-zips: ${msg}`);
}

function readShortVersion() {
    const html = fs.readFileSync(path.join(ROOT, 'Toolbox.html'), 'utf8');
    const match = html.match(/Version\s+(\d+)\.(\d+)\b/);
    if (!match) throw new Error('could not find "Version X.Y" in Toolbox.html');
    return `${match[1]}.${match[2]}`;
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

// Remove stale zips from earlier/other versions so release/ only holds the current one.
function cleanOldZips(keep) {
    if (!fs.existsSync(RELEASE_DIR)) return;
    for (const file of fs.readdirSync(RELEASE_DIR)) {
        if (/^CryptoToolbox\d+\.\d+\.zip$/.test(file) && !keep.includes(file)) {
            fs.unlinkSync(path.join(RELEASE_DIR, file));
            log(`removed stale ${file}`);
        }
    }
}

function main() {
    const version = readShortVersion();

    fs.mkdirSync(RELEASE_DIR, { recursive: true });

    const localZipName = `CryptoToolbox${version}.zip`;
    cleanOldZips([localZipName]);

    // Local browser bundle → staged into dist/local/CryptoToolbox<ver>/ then zipped.
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
