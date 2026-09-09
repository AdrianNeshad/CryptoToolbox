# <img src="build/icon-preview.png" width="32" alt="CryptoToolbox logo" align="top"> Crypto Toolbox

Local toolbox for **cryptography and crypto forensics**. Runs fully offline via .exe electron-app (or download the source and open `Toolbox.html` in your browser).

<p align="center">
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/archive/refs/tags/v3.0.zip"><img alt="Download source code (v2.8.zip)" src="https://img.shields.io/badge/Source-v2.8.zip-0a84ff?style=for-the-badge&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAAXNSR0IArs4c6QAAAHhlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAAGAAAAAAQAAAYAAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAABSgAwAEAAAAAQAAABQAAAAALPklgQAAAAlwSFlzAAA7DgAAOw4BzLahgwAAA9dJREFUOBGFVF1oXFUQnnPu7r0mm3QTmyabYmNabYXWPIg%2FD7YBf2NBEiw2ZhWK2RKpUEEiteCL4INIVWwJ%2BNCwNVFs0iUqtPiDhRRSfFGoYqNBCK2Joc1mgy1Jum527zln%2FM5m9zZqbYede2bOfDNnzsycFXQLakh23Std5xsmVqxVx1xiZPxmLvJmRmuTIfkquc4dwnWahZC9t8KL1YD1RzubqMrrCC2Y436U1hjNzwPwMjB3lnDT0I%2By5mE3JxdUlPZwjk7O9gxNl%2BMEAWMD8WZyxClZEW4x2cKvANSL20LrSJkydmUNSeJlNQ8lIyPuNpPzJ4wxHZnu1AULCK7MUrSXghE5cpsIyXWkmYwyl42vxooM2e4VbcDgYILPVodl%2B8ppqwKGfXXc%2FFU4LxxJAnmzocy15WzP3A8n7kk%2FcmhnuvnQzpzSLeTrfWw4YzE4mEzWH3e0%2BqQcMFQWjHQikOvJAg3P%2F7m08FShbWiJuqv7SModhIIsPPBpu6j2%2BhsHO88xhb8WkurR%2FfqS7xUbK7iykdQlvFDMppfP594otA4s0l3RUQRLALcZfJaq3CmsNNs9ck4o%2FabFos4NRtALdt%2BSiH3UuVV44V72TRtq08RKp9NfpTbxsP4QV7LBLH0B7hJCKGYOQ958e%2F9zlzzPmYDPelZmBqX61ijRJ0k6gxR2ekiKJutpmCY5MWmQWavVSzRWCmZLlAR%2FecV9N89sJpET7ik2YFZ7iPTnFsAlJ2uwYpgq7tbA5YN9ogPIzIW%2BHfwM%2BCI14zsFXkWoQBht0gl0LikMX0L3dF4tH6H7qBq4oL6QN4DfA9tguAaNibc2Ijm5pZgP8x9U0MeYdUcxJYuJDcb3L%2BtC9uqWwydpR9Nn2HrM7t%2BAfqfxzBNrv9%2F3qFcZSeIxEOf9g%2BkXU%2FbA4pAEPnx%2BupZa%2FhPsNwDsc8Ft6Du6kHnHHe2O1kVqTqNEdaxNWmp66PLeEzM2UDCHqFEt9H9ndoYmFjspt2aJ7seQvCS86PZd8bWRmreh1bGtPot5WaWyNpil4pVLwUagP17ctR%2FmM%2FTz9LM1P%2Fa2eW7FfrxpR0q5CWPSCJv9oakYhohLfM3vnU0MH7FuIQSzDUiB%2FxlsUeyu%2Fem1XRVuZVI4eBNoYZFszXJ6jgRnZKXXgj%2BHX5jFqRXjSic%2FgPJkeQPrKJx3ixpx1ZOePWwGg4u3jawMT%2BEBvC6ZHsznTasp6FdkTj09t3foYuCPDA%2BCy3Qagq1lQA0D8f7G1B62HPs4fiww%2FI9gm%2FI%2B2M4cBosO4EUsYb1ODvexrx62fWbBh68bbiz9Dcacpn9CYAckAAAAAElFTkSuQmCC&logoColor=white"></a>
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/releases/download/v3.0/magic.html"><img alt="Download standalone Magic Tool (magic.html)" src="https://img.shields.io/badge/Standalone-magic.html-0a84ff?style=for-the-badge&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAAXNSR0IArs4c6QAAAHhlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAAGAAAAAAQAAAYAAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAABSgAwAEAAAAAQAAABQAAAAALPklgQAAAAlwSFlzAAA7DgAAOw4BzLahgwAAA9dJREFUOBGFVF1oXFUQnnPu7r0mm3QTmyabYmNabYXWPIg%2FD7YBf2NBEiw2ZhWK2RKpUEEiteCL4INIVWwJ%2BNCwNVFs0iUqtPiDhRRSfFGoYqNBCK2Joc1mgy1Jum527zln%2FM5m9zZqbYede2bOfDNnzsycFXQLakh23Std5xsmVqxVx1xiZPxmLvJmRmuTIfkquc4dwnWahZC9t8KL1YD1RzubqMrrCC2Y436U1hjNzwPwMjB3lnDT0I%2By5mE3JxdUlPZwjk7O9gxNl%2BMEAWMD8WZyxClZEW4x2cKvANSL20LrSJkydmUNSeJlNQ8lIyPuNpPzJ4wxHZnu1AULCK7MUrSXghE5cpsIyXWkmYwyl42vxooM2e4VbcDgYILPVodl%2B8ppqwKGfXXc%2FFU4LxxJAnmzocy15WzP3A8n7kk%2FcmhnuvnQzpzSLeTrfWw4YzE4mEzWH3e0%2BqQcMFQWjHQikOvJAg3P%2F7m08FShbWiJuqv7SModhIIsPPBpu6j2%2BhsHO88xhb8WkurR%2FfqS7xUbK7iykdQlvFDMppfP594otA4s0l3RUQRLALcZfJaq3CmsNNs9ck4o%2FabFos4NRtALdt%2BSiH3UuVV44V72TRtq08RKp9NfpTbxsP4QV7LBLH0B7hJCKGYOQ958e%2F9zlzzPmYDPelZmBqX61ijRJ0k6gxR2ekiKJutpmCY5MWmQWavVSzRWCmZLlAR%2FecV9N89sJpET7ik2YFZ7iPTnFsAlJ2uwYpgq7tbA5YN9ogPIzIW%2BHfwM%2BCI14zsFXkWoQBht0gl0LikMX0L3dF4tH6H7qBq4oL6QN4DfA9tguAaNibc2Ijm5pZgP8x9U0MeYdUcxJYuJDcb3L%2BtC9uqWwydpR9Nn2HrM7t%2BAfqfxzBNrv9%2F3qFcZSeIxEOf9g%2BkXU%2FbA4pAEPnx%2BupZa%2FhPsNwDsc8Ft6Du6kHnHHe2O1kVqTqNEdaxNWmp66PLeEzM2UDCHqFEt9H9ndoYmFjspt2aJ7seQvCS86PZd8bWRmreh1bGtPot5WaWyNpil4pVLwUagP17ctR%2FmM%2FTz9LM1P%2Fa2eW7FfrxpR0q5CWPSCJv9oakYhohLfM3vnU0MH7FuIQSzDUiB%2FxlsUeyu%2Fem1XRVuZVI4eBNoYZFszXJ6jgRnZKXXgj%2BHX5jFqRXjSic%2FgPJkeQPrKJx3ixpx1ZOePWwGg4u3jawMT%2BEBvC6ZHsznTasp6FdkTj09t3foYuCPDA%2BCy3Qagq1lQA0D8f7G1B62HPs4fiww%2FI9gm%2FI%2B2M4cBosO4EUsYb1ODvexrx62fWbBh68bbiz9Dcacpn9CYAckAAAAAElFTkSuQmCC&logoColor=white"></a>
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/releases/download/v3.0/CryptoToolbox3.0.exe"><img alt="Download Windows app (Verktygsladan2.8.exe)" src="https://img.shields.io/badge/Windows-Verktygsladan2.8.exe-0a84ff?style=for-the-badge&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAAXNSR0IArs4c6QAAAHhlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAAGAAAAAAQAAAYAAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAABSgAwAEAAAAAQAAABQAAAAALPklgQAAAAlwSFlzAAA7DgAAOw4BzLahgwAAA9dJREFUOBGFVF1oXFUQnnPu7r0mm3QTmyabYmNabYXWPIg%2FD7YBf2NBEiw2ZhWK2RKpUEEiteCL4INIVWwJ%2BNCwNVFs0iUqtPiDhRRSfFGoYqNBCK2Joc1mgy1Jum527zln%2FM5m9zZqbYede2bOfDNnzsycFXQLakh23Std5xsmVqxVx1xiZPxmLvJmRmuTIfkquc4dwnWahZC9t8KL1YD1RzubqMrrCC2Y436U1hjNzwPwMjB3lnDT0I%2By5mE3JxdUlPZwjk7O9gxNl%2BMEAWMD8WZyxClZEW4x2cKvANSL20LrSJkydmUNSeJlNQ8lIyPuNpPzJ4wxHZnu1AULCK7MUrSXghE5cpsIyXWkmYwyl42vxooM2e4VbcDgYILPVodl%2B8ppqwKGfXXc%2FFU4LxxJAnmzocy15WzP3A8n7kk%2FcmhnuvnQzpzSLeTrfWw4YzE4mEzWH3e0%2BqQcMFQWjHQikOvJAg3P%2F7m08FShbWiJuqv7SModhIIsPPBpu6j2%2BhsHO88xhb8WkurR%2FfqS7xUbK7iykdQlvFDMppfP594otA4s0l3RUQRLALcZfJaq3CmsNNs9ck4o%2FabFos4NRtALdt%2BSiH3UuVV44V72TRtq08RKp9NfpTbxsP4QV7LBLH0B7hJCKGYOQ958e%2F9zlzzPmYDPelZmBqX61ijRJ0k6gxR2ekiKJutpmCY5MWmQWavVSzRWCmZLlAR%2FecV9N89sJpET7ik2YFZ7iPTnFsAlJ2uwYpgq7tbA5YN9ogPIzIW%2BHfwM%2BCI14zsFXkWoQBht0gl0LikMX0L3dF4tH6H7qBq4oL6QN4DfA9tguAaNibc2Ijm5pZgP8x9U0MeYdUcxJYuJDcb3L%2BtC9uqWwydpR9Nn2HrM7t%2BAfqfxzBNrv9%2F3qFcZSeIxEOf9g%2BkXU%2FbA4pAEPnx%2BupZa%2FhPsNwDsc8Ft6Du6kHnHHe2O1kVqTqNEdaxNWmp66PLeEzM2UDCHqFEt9H9ndoYmFjspt2aJ7seQvCS86PZd8bWRmreh1bGtPot5WaWyNpil4pVLwUagP17ctR%2FmM%2FTz9LM1P%2Fa2eW7FfrxpR0q5CWPSCJv9oakYhohLfM3vnU0MH7FuIQSzDUiB%2FxlsUeyu%2Fem1XRVuZVI4eBNoYZFszXJ6jgRnZKXXgj%2BHX5jFqRXjSic%2FgPJkeQPrKJx3ixpx1ZOePWwGg4u3jawMT%2BEBvC6ZHsznTasp6FdkTj09t3foYuCPDA%2BCy3Qagq1lQA0D8f7G1B62HPs4fiww%2FI9gm%2FI%2B2M4cBosO4EUsYb1ODvexrx62fWbBh68bbiz9Dcacpn9CYAckAAAAAElFTkSuQmCC&logoColor=white"></a>
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
