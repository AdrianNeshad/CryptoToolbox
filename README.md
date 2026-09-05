# <img src="build/icon-preview.png" width="32" alt="Verktygslådans logga" align="top"> Verktygslådan (CryptoToolbox)

Lokal verktygslåda för **kryptografi och krypto-forensik**. Körs helt offline via Electron (eller ladda ner källkoden och öppna `Toolbox.html` i webbläsaren).

## Verktyg (v2.8)

### Magic Tool - Klistra in valfri text och detektera kryptorelaterade strängar med checksum-verifiering
<img width="1511" height="822" alt="Screenshot 2026-09-05 at 13 54 32" src="https://github.com/user-attachments/assets/58f8262b-782b-4752-b2bf-ac77677ee86b" />

### Brute Force Tools
<img width="1512" height="826" alt="Screenshot 2026-09-05 at 13 59 09" src="https://github.com/user-attachments/assets/d7945323-7cec-4900-8bf6-61f68b34ee03" />

### Konvertering & Format

| Verktyg | Beskrivning |
|---------|-------------|
| Magic Tool | Klistra in valfri text — nycklar, adresser, entropi och krypteringsmetadata identifieras automatiskt |
| BIP38 Key Compression | Komprimera/dekomprimera Bitcoin-nycklar |
| QR Code Decoder | Avkoda QR-koder från bilder |
| JSON Formatter | Compact JSON → pretty print / minifiera, avkodar även JWT |
| Time Converter | Konvertera tidsstämplar (Unix, Apple NSDate, WebKit, FILETIME, m.m.) |

### BIP39 & Seed

| Verktyg | Beskrivning |
|---------|-------------|
| Entropy to Mnemonic | Konvertera entropi-bytes till BIP39-fras |
| BIP39 Tool | Komplett BIP39-verktyg (mnemonic ↔ seed, derivation paths, adresser) |
| BIP39 English Word List | Alla BIP39-ord med sökfunktion |
| BIP39 Checksum Finder | Sista checksum-ordet (12 & 24 ord) |

### Övrigt

| Verktyg | Beskrivning |
|---------|-------------|
| Diff Checker | Jämför två texter rad för rad |
| CyberChef | Offline encoding / decoding / crypto |
| BalletCrypto Cold Storage Decoder | Dekryptera BalletCrypto-kort |

### Brute Force

| Verktyg | Beskrivning |
|---------|-------------|
| Exodus seed.seco Unlock | Brute force av Exodus `seed.seco`-filer (dictionary attack) |
| Electrum Wallet Unlock | Brute force av Electrum-plånboksfiler (dictionary attack) |
| MetaMask Vault Decryptor | Brute force av MetaMask-vault (dictionary attack) |
| Ethereum Keystore Unlock | Brute force av Ethereum keystore (dictionary attack) |

## Kom igång

Node.js 20+ (inkl. npm).

```bash
brew install node
```

## Köra / testa

Snabbast — ingen paketering:

```bash
npm install
npm start          # Electron-fönster (rekommenderas för test)
```

Eller öppna `Toolbox.html` i webbläsaren (de flesta verktyg funkar så).

Snabb “dir”-pack utan installer:

```bash
npm run pack       # electron-builder --dir → release/win-unpacked/
```

## Bygga för Windows

**Lokal Windows-maskin** (eller CI):

```bash
npm install
npm run dist            # NSIS-installer + portable .exe → release/
# eller enskilt:
npm run dist:installer  # bara NSIS-installer
npm run dist:portable   # bara portable .exe
```

**CI (rekommenderas):** GitHub Actions bygger Windows-appen och publicerar en Release
(`.github/workflows/build-windows-app.yml`) vid push till `main`. Ändringar som bara
rör `.md`-filer triggar ingen ny build.

| Mål | Kommando | Output |
|-----|----------|--------|
| Testa nu | `npm start` | Electron live |
| Snabb dir-pack | `npm run pack` | `release/win-unpacked/` |
| Windows installer | `npm run dist:installer` | `release/*.exe` (NSIS) |
| Windows portable | `npm run dist:portable` | `release/Verktygslådan-Portable-*.exe` |
| Windows (båda) | `npm run dist` | `release/*.exe` |

## Lägga till ett eget verktyg

1. Skapa `tools/<namn>/` med HTML/JS/CSS
2. Lägg till en knapp i `Toolbox.html` med `data-type="frame"` och `data-src="tools/<namn>/..."`
3. Lyssna på tema via `postMessage` (`source: 'verktygslada'`)

## Attribution

- CyberChef: [GCHQ/CyberChef](https://github.com/gchq/CyberChef)
- BIP39 Mnemonic Code Converter & Bitcoin Key Compression Tool: [GitHub/iancoleman](https://github.com/iancoleman)
- QR-avkodning: [cozmo/jsQR](https://github.com/cozmo/jsQR)

## Licens

Släppt under [MIT-licensen](LICENSE). © 2026 Adrian Neshad.
