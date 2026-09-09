#!/usr/bin/env node
// Renders build/icon-source.svg to a Windows .ico (build/icon.ico) with multiple
// resolutions, plus a 512px PNG preview (build/icon-preview.png).
//
// Run manually when the icon needs to be changed/updated: `node scripts/generate-icon.js`
// (requires devDependencies sharp + png-to-ico, run `npm install` first).

const fs = require('node:fs');
const path = require('node:path');
const sharp = require('sharp');
const pngToIco = require('png-to-ico').default;

const ROOT = path.join(__dirname, '..');
const SVG_PATH = path.join(ROOT, 'build', 'icon-source.svg');
const ICO_PATH = path.join(ROOT, 'build', 'icon.ico');
const PREVIEW_PATH = path.join(ROOT, 'build', 'icon-preview.png');

const SIZES = [16, 24, 32, 48, 64, 128, 256];

async function main() {
    const svg = fs.readFileSync(SVG_PATH);

    const pngBuffers = await Promise.all(
        SIZES.map((size) => sharp(svg, { density: 384 }).resize(size, size).png().toBuffer())
    );

    const icoBuffer = await pngToIco(pngBuffers);
    fs.writeFileSync(ICO_PATH, icoBuffer);
    console.log(`generate-icon: wrote ${ICO_PATH} (${SIZES.join(', ')}px)`);

    // Separate, larger PNG for a quick visual check (Windows icons cannot be
    // previewed directly in an image viewer the way a regular PNG can).
    await sharp(svg, { density: 384 }).resize(512, 512).png().toFile(PREVIEW_PATH);
    console.log(`generate-icon: wrote ${PREVIEW_PATH} (preview)`);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
