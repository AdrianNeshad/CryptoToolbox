# <img src="build/icon-preview.png" width="32" alt="Verktygslådans logga" align="top"> Verktygslådan (CryptoToolbox)

Lokal verktygslåda för **kryptografi och krypto-forensik**. Körs helt offline via Electron (eller ladda ner källkoden och öppna `Toolbox.html` i webbläsaren).

## Verktyg (v1.6)

| Verktyg | Beskrivning |
|---------|-------------|
| Magic Tool | Klistra in valfri text — nycklar, adresser, entropi och krypteringsmetadata identifieras automatiskt |
| BIP38 Key Compression | Komprimera/dekomprimera Bitcoin-nycklar |
| QR Code Decoder | Avkoda QR-koder från bilder |
| JSON Formatter | Compact JSON → pretty print / validera |
| Entropy to Mnemonic | Konvertera entropi-bytes till BIP39-fras |
| BIP39 Tool | Komplett BIP39-verktyg (mnemonic ↔ seed, derivation paths, adresser) |
| BIP39 English Word List | Alla BIP39-ord med sökfunktion |
| BIP39 Checksum Finder | Sista checksum-ordet (12 & 24 ord) |
| CyberChef | Offline encoding / decoding / crypto |
| BalletCrypto Cold Storage Decoder | Dekryptera BalletCrypto-kort |

## Dokumentation & extramaterial

- **Krypto wallets lagring** – wallet-lagringsformat och kryptering (`documentation/wallets.html`)
- **Phantom Wallet Decryption** – entropy & JSON decryption (`documentation/phantom.pdf`)

### Nedladdningar / skript

- **Exodus secoUnlock** – lås upp Exodus `seed.seco`-filer med dictionary attack (.zip)
- **Electrum Unlock** – lås upp Electrum-plånboksfiler med dictionary attack (.zip)
- **Ciphertext Unlock** – brute force ciphertext med dictionary attack (.zip)

### Externa länkar

- **Learn Me A Bitcoin** – teknisk information om Bitcoin
- **USDT Freeze Checker** – Blocksec
- **OSINT4ALL** – kollektion av OSINT-verktyg

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

Alla `dist`-kommandon kör först `sync-version` (matchar `package.json`-versionen) och
`finalize-artifacts` (namnger/flyttar färdiga filer i `release/`) automatiskt.

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

## Lägga till ett verktyg

1. Skapa `tools/<namn>/` med HTML/JS/CSS
2. Lägg till en knapp i `Toolbox.html` med `data-type="frame"` och `data-src="tools/<namn>/..."`
3. Lyssna på tema via `postMessage` (`source: 'verktygslada'`)

## Attribution

- CyberChef: [GCHQ/CyberChef](https://github.com/gchq/CyberChef)
- BIP39 Mnemonic Code Converter & Bitcoin Key Compression Tool: [GitHub/iancoleman](https://github.com/iancoleman)