# <img src="build/icon-preview.png" width="32" alt="CryptoToolbox logo" align="top"> Crypto Toolbox

Local toolbox for **cryptography and crypto forensics**. Runs fully offline via .exe electron-app, as a Chrome extension, or by downloading the source and opening `Toolbox.html` in your browser.

<p align="center">
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/archive/refs/tags/v3.0.zip"><img alt="Download source code (v2.8.zip)" height="28" src="https://img.shields.io/badge/Source-CryptoToolbox.zip-0a84ff?style=plastic&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI0U4OTcxRSIgZD0iTTMgNi41QzMgNS42NyAzLjY3IDUgNC41IDVIOS4yTDExLjIgN0gxOS41QzIwLjMzIDcgMjEgNy42NyAyMSA4LjVWMTBIM1Y2LjVaIi8%2BPHBhdGggZmlsbD0iI0ZCQkYyNCIgZD0iTTMgOUgyMVYxNy41QzIxIDE4LjMzIDIwLjMzIDE5IDE5LjUgMTlINC41QzMuNjcgMTkgMyAxOC4zMyAzIDE3LjVWOVoiLz48L3N2Zz4%3D"></a>
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/releases/download/v3.0/magic.html"><img alt="Download standalone Magic Tool (magic.html)" height="28" src="https://img.shields.io/badge/Standalone-magic.html-0a84ff?style=plastic&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHJlY3QgeD0iMSIgeT0iMSIgd2lkdGg9IjIyIiBoZWlnaHQ9IjIyIiByeD0iNiIgZmlsbD0iIzMwZDE1OCIvPjxnIHRyYW5zZm9ybT0idHJhbnNsYXRlKDUuMzMgNS4zMykgc2NhbGUoMC41NTYpIiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmYiIHN0cm9rZS13aWR0aD0iMi40IiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTUgMkwxNi42IDcuNEwyMiA5TDE2LjYgMTAuNkwxNSAxNkwxMy40IDEwLjZMOCA5TDEzLjQgNy40TDE1IDJaIi8%2BPHBhdGggZD0iTTYgMTJMNyAxNUwxMCAxNkw3IDE3TDYgMjBMNSAxN0wyIDE2TDUgMTVMNiAxMloiLz48L2c%2BPC9zdmc%2B"></a>
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/releases/download/v3.0/CryptoToolbox3.0.exe"><img alt="Download Windows app (CryptoToolbox.exe)" height="28" src="https://img.shields.io/badge/Windows-CryptoToolbox.exe-0a84ff?style=plastic&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iIzAwQTRFRiIgZD0iTTMgNC41TDExLjIgMy4zNVYxMS4zNUgzVjQuNVoiLz48cGF0aCBmaWxsPSIjMDBBNEVGIiBkPSJNMTIuMyAzLjJMMjEgMlYxMS4zNUgxMi4zVjMuMloiLz48cGF0aCBmaWxsPSIjMDBBNEVGIiBkPSJNMyAxMi41NUgxMS4yVjIwLjY1TDMgMTkuNVYxMi41NVoiLz48cGF0aCBmaWxsPSIjMDBBNEVGIiBkPSJNMTIuMyAxMi41NUgyMVYyMkwxMi4zIDIwLjhWMTIuNTVaIi8%2BPC9zdmc%2B"></a>
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/releases/download/v3.0/CryptoToolbox3.0-Chrome-Extension.zip"><img alt="Download Chrome extension (CryptoToolbox-Chrome-Extension.zip)" height="28" src="https://img.shields.io/badge/Chrome-Extension.zip-0a84ff?style=plastic&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OCA0OCI%2BPHBhdGggZmlsbD0iI0VBNDMzNSIgZD0iTTI0IDI0IEw0Ljk1IDEzIEEyMiAyMiAwIDAgMSA0My4wNSAxMyBaIi8%2BPHBhdGggZmlsbD0iI0ZCQkMwNSIgZD0iTTI0IDI0IEw0My4wNSAxMyBBMjIgMjIgMCAwIDEgMjQgNDYgWiIvPjxwYXRoIGZpbGw9IiMzNEE4NTMiIGQ9Ik0yNCAyNCBMMjQgNDYgQTIyIDIyIDAgMCAxIDQuOTUgMTMgWiIvPjxwYXRoIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjYiIGQ9Ik0yNCAyNCBMMjQgNDYgTTI0IDI0IEw0Ljk1IDEzIE0yNCAyNCBMNDMuMDUgMTMiLz48Y2lyY2xlIGN4PSIyNCIgY3k9IjI0IiByPSIxMCIgZmlsbD0iI2ZmZiIvPjxjaXJjbGUgY3g9IjI0IiBjeT0iMjQiIHI9IjgiIGZpbGw9IiM0Mjg1RjQiLz48L3N2Zz4%3D"></a>
</p>

## Tools (v3.0)

### Magic Tool - Paste any text and detect crypto-related strings with checksum verification
<img width="1512" height="827" alt="Screenshot 2026-09-09 at 18 01 01" src="https://github.com/user-attachments/assets/db6af8cd-9a13-4f26-8f5a-43b61beedd05" />

### Brute Force Tools
<img width="1512" height="828" alt="Screenshot 2026-09-09 at 18 01 58" src="https://github.com/user-attachments/assets/e637a39d-0248-46ae-926c-90ad68e7e6af" />

### Conversion & Format

| Tool | Description |
|---------|-------------|
| Magic Tool | Paste any text — keys, addresses, entropy, and encryption metadata are detected automatically |
| BIP38 Key Compression | Compress/decompress Bitcoin keys |
| QR Code Decoder | Decode QR codes from images |
| JSON Formatter | Compact JSON → pretty print / minify, also decodes JWT |
| Time Converter | Convert timestamps (Unix, Apple NSDate, WebKit, FILETIME, etc.) |

### BIP39 & Seed

| Tool | Description |
|---------|-------------|
| Entropy to Mnemonic | Convert entropy bytes to a BIP39 phrase |
| BIP39 Tool | Complete BIP39 tool |
| BIP39 English Word List | All BIP39 words with search |
| BIP39 Checksum Finder | Final checksum word (12 & 24 words) |

### Other

| Tool | Description |
|---------|-------------|
| Diff Checker | Compare two texts line by line |
| CyberChef | Offline encoding / decoding / crypto |
| BalletCrypto Cold Storage Decoder | Decrypt BalletCrypto cards |

### Brute Force

| Tool | Description |
|---------|-------------|
| Monero .keys Recovery | Brute-force Monero `.keys` files (dictionary attack) |
| Exodus seed.seco Unlock | Brute-force Exodus `.seco` files (dictionary attack) |
| Electrum Wallet Unlock | Brute-force Electrum wallet files (dictionary attack) |
| MetaMask Vault Decryptor | Brute-force MetaMask vault (dictionary attack) |
| Ethereum Keystore Unlock | Brute-force Ethereum keystore (dictionary attack) |

## Getting started

Node.js 20+ (incl. npm).

```bash
brew install node
```

## Run / test

Fastest — no packaging:

```bash
npm install
npm start          # Electron window (recommended for testing)
```

Or open `Toolbox.html` in your browser (most tools work that way).

Quick “dir” pack without an installer:

```bash
npm run pack       # electron-builder --dir → release/win-unpacked/
```

## Build for Windows

**Local Windows machine** (or CI):

```bash
npm install
npm run dist            # NSIS-installer + portable .exe → release/
# or individually:
npm run dist:installer  # NSIS installer only
npm run dist:portable   # portable .exe only
```

**CI (recommended):** GitHub Actions builds the Windows app and publishes a Release
(`.github/workflows/build-windows-app.yml`) on push to `main`. Changes that only
touch `.md` files do not trigger a new build.

| Target | Command | Output |
|-----|----------|--------|
| Test now | `npm start` | Electron live |
| Quick dir pack | `npm run pack` | `release/win-unpacked/` |
| Windows installer | `npm run dist:installer` | `release/*.exe` (NSIS) |
| Windows portable | `npm run dist:portable` | `release/CryptoToolbox-Portable-*.exe` |
| Windows (both) | `npm run dist` | `release/*.exe` |

## Add your own tool

1. Create `tools/<name>/` with HTML/JS/CSS
2. Add a button in `Toolbox.html` with `data-type="frame"` and `data-src="tools/<name>/..."`
3. Listen for the theme via `postMessage` (`source: 'cryptotoolbox'`)

## Attribution

- Time Converter: [Overwatched/Forensics-Toolbox](https://github.com/Overwatched/Forensics-Toolbox)
- CyberChef: [GCHQ/CyberChef](https://github.com/gchq/CyberChef)
- QR decoding: [cozmo/jsQR](https://github.com/cozmo/jsQR)
- BIP39: [iancoleman/bip39](https://github.com/iancoleman/bip39)

## License

Released under the [MIT license](LICENSE). © 2026 Adrian Neshad.

## Use responsibly
### “The blade itself incites to deeds of violence.” - Homer, The Odyssey
