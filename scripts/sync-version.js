#!/usr/bin/env node
// Läser "Version X.Y" från Toolbox.html (samma text som visas i sidopanelen i appen)
// och synkar den till package.json, så att electron-builder och filnamnet på den
// byggda .exe-filen alltid matchar det som står i appen — utan att versionen behöver
// underhållas på två ställen.
//
// Körs automatiskt som en del av `npm run dist` / `npm run dist:portable` /
// `npm run dist:installer`, och av CI-workflowen (.github/workflows/build-windows-app.yml).
// Kan även köras manuellt: `node scripts/sync-version.js`

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const TOOLBOX_HTML = path.join(ROOT, 'Toolbox.html');
const PACKAGE_JSON = path.join(ROOT, 'package.json');

const html = fs.readFileSync(TOOLBOX_HTML, 'utf8');
const match = html.match(/Version\s+(\d+)\.(\d+)\b/);

if (!match) {
    console.error('sync-version: kunde inte hitta "Version X.Y" i Toolbox.html');
    process.exit(1);
}

const [, major, minor] = match;
const shortVersion = `${major}.${minor}`; // t.ex. "1.6" — används i filnamnet på .exe-filen
const semver = `${major}.${minor}.0`; // t.ex. "1.6.0" — giltig semver, krävs av electron-builder

const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, 'utf8'));
if (pkg.version !== semver) {
    pkg.version = semver;
    fs.writeFileSync(PACKAGE_JSON, JSON.stringify(pkg, null, 2) + '\n');
}

console.log(`sync-version: Toolbox.html säger version ${shortVersion} -> package.json satt till ${semver}`);

// Om vi körs i GitHub Actions: exponera kortversionen så att workflowen kan använda
// den för release-taggen (v1.6) och i loggar.
if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `version=${shortVersion}\n`);
}
if (process.env.GITHUB_ENV) {
    fs.appendFileSync(process.env.GITHUB_ENV, `APP_VERSION=${shortVersion}\n`);
}
