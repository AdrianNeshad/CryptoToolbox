#!/usr/bin/env node
// Renderar build/icon-source.svg till en Windows .ico (build/icon.ico) med flera
// upplösningar, plus en 512px PNG-förhandsvisning (build/icon-preview.png).
//
// Körs manuellt när ikonen ska bytas/uppdateras: `node scripts/generate-icon.js`
// (kräver devDependencies sharp + png-to-ico, `npm install` först).

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
    console.log(`generate-icon: skrev ${ICO_PATH} (${SIZES.join(', ')}px)`);

    // Separat, större PNG för snabb visuell koll (Windows-ikoner går inte att
    // förhandsgranska direkt i en bildvisare på samma sätt som en vanlig PNG).
    await sharp(svg, { density: 384 }).resize(512, 512).png().toFile(PREVIEW_PATH);
    console.log(`generate-icon: skrev ${PREVIEW_PATH} (förhandsvisning)`);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
