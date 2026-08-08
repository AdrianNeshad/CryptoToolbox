#!/usr/bin/env node
// Döper om de filer electron-builder just byggde i release/ till det slutgiltiga,
// användarvända namnet: "VerktygslådanX.Y.exe" (portabel) och
// "VerktygslådanX.Y Installer.exe" (NSIS-installer) — där X.Y alltid är samma
// version som visas i Toolbox.htmls sidopanel.
//
// Körs automatiskt efter `npm run dist` / `dist:portable` / `dist:installer`.

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const RELEASE_DIR = path.join(ROOT, 'release');

const html = fs.readFileSync(path.join(ROOT, 'Toolbox.html'), 'utf8');
const match = html.match(/Version\s+(\d+)\.(\d+)\b/);
if (!match) {
    console.error('finalize-artifacts: kunde inte hitta "Version X.Y" i Toolbox.html');
    process.exit(1);
}
const shortVersion = `${match[1]}.${match[2]}`;

if (!fs.existsSync(RELEASE_DIR)) {
    console.error(`finalize-artifacts: hittar inte byggmappen ${RELEASE_DIR}`);
    process.exit(1);
}

const portableName = `Verktygslådan${shortVersion}.exe`;
const installerName = `Verktygslådan${shortVersion} Installer.exe`;

// Städa bort ev. tidigare omdöpta filer från lokala testbyggen av en annan version,
// så de inte ligger kvar och skapar förvirring bredvid den nya byggen.
for (const file of fs.readdirSync(RELEASE_DIR)) {
    if (/^Verktygslådan\d+\.\d+( Installer)?\.exe$/.test(file) && file !== portableName && file !== installerName) {
        fs.unlinkSync(path.join(RELEASE_DIR, file));
    }
}

function renameFirstMatch(pattern, targetName) {
    const files = fs.readdirSync(RELEASE_DIR);
    const found = files.find((f) => pattern.test(f));
    if (!found) {
        console.warn(`finalize-artifacts: hittade ingen fil som matchar ${pattern} i release/ — hoppar över.`);
        return;
    }
    const from = path.join(RELEASE_DIR, found);
    const to = path.join(RELEASE_DIR, targetName);
    if (from !== to) {
        fs.renameSync(from, to);
    }
    console.log(`finalize-artifacts: ${found} -> ${targetName}`);
}

renameFirstMatch(/^Verktygslådan-Portable-.*\.exe$/i, portableName);
renameFirstMatch(/^Verktygslådan Setup .*\.exe$/i, installerName);
