#!/usr/bin/env node
// Reads "Version X.Y" from Toolbox.html (the same text shown in the app sidebar)
// and syncs it to package.json, so that electron-builder and the filename of the
// built .exe file always match what the app shows — without the version needing
// to be maintained in two places.
//
// Runs automatically as part of `npm run dist` / `npm run dist:portable` /
// `npm run dist:installer`, and by the CI workflow (.github/workflows/build-windows-app.yml).
// Can also be run manually: `node scripts/sync-version.js`

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const TOOLBOX_HTML = path.join(ROOT, 'Toolbox.html');
const PACKAGE_JSON = path.join(ROOT, 'package.json');

const html = fs.readFileSync(TOOLBOX_HTML, 'utf8');
const match = html.match(/Version\s+(\d+)\.(\d+)\b/);

if (!match) {
    console.error('sync-version: could not find "Version X.Y" in Toolbox.html');
    process.exit(1);
}

const [, major, minor] = match;
const shortVersion = `${major}.${minor}`; // e.g. "1.6" — used in the .exe filename
const semver = `${major}.${minor}.0`; // e.g. "1.6.0" — valid semver, required by electron-builder

const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, 'utf8'));
if (pkg.version !== semver) {
    pkg.version = semver;
    fs.writeFileSync(PACKAGE_JSON, JSON.stringify(pkg, null, 2) + '\n');
}

console.log(`sync-version: Toolbox.html says version ${shortVersion} -> package.json set to ${semver}`);

// If running in GitHub Actions: expose the short version so the workflow can use it
// for the release tag (v1.6) and in logs.
if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `version=${shortVersion}\n`);
}
if (process.env.GITHUB_ENV) {
    fs.appendFileSync(process.env.GITHUB_ENV, `APP_VERSION=${shortVersion}\n`);
}
