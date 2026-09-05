# <img src="build/icon-preview.png" width="32" alt="Verktygslådans logga" align="top"> Verktygslådan (CryptoToolbox)

Lokal verktygslåda för **kryptografi och krypto-forensik**. Körs helt offline via Electron (eller ladda ner källkoden och öppna `Toolbox.html` i webbläsaren).

<p align="center">
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/archive/refs/tags/v2.8.zip"><img alt="Ladda ner källkod (v2.8.zip)" src="https://img.shields.io/badge/K%C3%A4llkod-v2.8.zip-0a84ff?style=for-the-badge&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAAXNSR0IArs4c6QAAAHhlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAAGAAAAAAQAAAYAAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAABSgAwAEAAAAAQAAABQAAAAALPklgQAAAAlwSFlzAAA7DgAAOw4BzLahgwAAA9dJREFUOBGFVF1oXFUQnnPu7r0mm3QTmyabYmNabYXWPIg%2FD7YBf2NBEiw2ZhWK2RKpUEEiteCL4INIVWwJ%2BNCwNVFs0iUqtPiDhRRSfFGoYqNBCK2Joc1mgy1Jum527zln%2FM5m9zZqbYede2bOfDNnzsycFXQLakh23Std5xsmVqxVx1xiZPxmLvJmRmuTIfkquc4dwnWahZC9t8KL1YD1RzubqMrrCC2Y436U1hjNzwPwMjB3lnDT0I%2By5mE3JxdUlPZwjk7O9gxNl%2BMEAWMD8WZyxClZEW4x2cKvANSL20LrSJkydmUNSeJlNQ8lIyPuNpPzJ4wxHZnu1AULCK7MUrSXghE5cpsIyXWkmYwyl42vxooM2e4VbcDgYILPVodl%2B8ppqwKGfXXc%2FFU4LxxJAnmzocy15WzP3A8n7kk%2FcmhnuvnQzpzSLeTrfWw4YzE4mEzWH3e0%2BqQcMFQWjHQikOvJAg3P%2F7m08FShbWiJuqv7SModhIIsPPBpu6j2%2BhsHO88xhb8WkurR%2FfqS7xUbK7iykdQlvFDMppfP594otA4s0l3RUQRLALcZfJaq3CmsNNs9ck4o%2FabFos4NRtALdt%2BSiH3UuVV44V72TRtq08RKp9NfpTbxsP4QV7LBLH0B7hJCKGYOQ958e%2F9zlzzPmYDPelZmBqX61ijRJ0k6gxR2ekiKJutpmCY5MWmQWavVSzRWCmZLlAR%2FecV9N89sJpET7ik2YFZ7iPTnFsAlJ2uwYpgq7tbA5YN9ogPIzIW%2BHfwM%2BCI14zsFXkWoQBht0gl0LikMX0L3dF4tH6H7qBq4oL6QN4DfA9tguAaNibc2Ijm5pZgP8x9U0MeYdUcxJYuJDcb3L%2BtC9uqWwydpR9Nn2HrM7t%2BAfqfxzBNrv9%2F3qFcZSeIxEOf9g%2BkXU%2FbA4pAEPnx%2BupZa%2FhPsNwDsc8Ft6Du6kHnHHe2O1kVqTqNEdaxNWmp66PLeEzM2UDCHqFEt9H9ndoYmFjspt2aJ7seQvCS86PZd8bWRmreh1bGtPot5WaWyNpil4pVLwUagP17ctR%2FmM%2FTz9LM1P%2Fa2eW7FfrxpR0q5CWPSCJv9oakYhohLfM3vnU0MH7FuIQSzDUiB%2FxlsUeyu%2Fem1XRVuZVI4eBNoYZFszXJ6jgRnZKXXgj%2BHX5jFqRXjSic%2FgPJkeQPrKJx3ixpx1ZOePWwGg4u3jawMT%2BEBvC6ZHsznTasp6FdkTj09t3foYuCPDA%2BCy3Qagq1lQA0D8f7G1B62HPs4fiww%2FI9gm%2FI%2B2M4cBosO4EUsYb1ODvexrx62fWbBh68bbiz9Dcacpn9CYAckAAAAAElFTkSuQmCC&logoColor=white"></a>
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/releases/download/v2.8/magic.html"><img alt="Ladda ner standalone Magic Tool (magic.html)" src="https://img.shields.io/badge/Standalone-magic.html-0a84ff?style=for-the-badge&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAAXNSR0IArs4c6QAAAHhlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAAGAAAAAAQAAAYAAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAABSgAwAEAAAAAQAAABQAAAAALPklgQAAAAlwSFlzAAA7DgAAOw4BzLahgwAAA9dJREFUOBGFVF1oXFUQnnPu7r0mm3QTmyabYmNabYXWPIg%2FD7YBf2NBEiw2ZhWK2RKpUEEiteCL4INIVWwJ%2BNCwNVFs0iUqtPiDhRRSfFGoYqNBCK2Joc1mgy1Jum527zln%2FM5m9zZqbYede2bOfDNnzsycFXQLakh23Std5xsmVqxVx1xiZPxmLvJmRmuTIfkquc4dwnWahZC9t8KL1YD1RzubqMrrCC2Y436U1hjNzwPwMjB3lnDT0I%2By5mE3JxdUlPZwjk7O9gxNl%2BMEAWMD8WZyxClZEW4x2cKvANSL20LrSJkydmUNSeJlNQ8lIyPuNpPzJ4wxHZnu1AULCK7MUrSXghE5cpsIyXWkmYwyl42vxooM2e4VbcDgYILPVodl%2B8ppqwKGfXXc%2FFU4LxxJAnmzocy15WzP3A8n7kk%2FcmhnuvnQzpzSLeTrfWw4YzE4mEzWH3e0%2BqQcMFQWjHQikOvJAg3P%2F7m08FShbWiJuqv7SModhIIsPPBpu6j2%2BhsHO88xhb8WkurR%2FfqS7xUbK7iykdQlvFDMppfP594otA4s0l3RUQRLALcZfJaq3CmsNNs9ck4o%2FabFos4NRtALdt%2BSiH3UuVV44V72TRtq08RKp9NfpTbxsP4QV7LBLH0B7hJCKGYOQ958e%2F9zlzzPmYDPelZmBqX61ijRJ0k6gxR2ekiKJutpmCY5MWmQWavVSzRWCmZLlAR%2FecV9N89sJpET7ik2YFZ7iPTnFsAlJ2uwYpgq7tbA5YN9ogPIzIW%2BHfwM%2BCI14zsFXkWoQBht0gl0LikMX0L3dF4tH6H7qBq4oL6QN4DfA9tguAaNibc2Ijm5pZgP8x9U0MeYdUcxJYuJDcb3L%2BtC9uqWwydpR9Nn2HrM7t%2BAfqfxzBNrv9%2F3qFcZSeIxEOf9g%2BkXU%2FbA4pAEPnx%2BupZa%2FhPsNwDsc8Ft6Du6kHnHHe2O1kVqTqNEdaxNWmp66PLeEzM2UDCHqFEt9H9ndoYmFjspt2aJ7seQvCS86PZd8bWRmreh1bGtPot5WaWyNpil4pVLwUagP17ctR%2FmM%2FTz9LM1P%2Fa2eW7FfrxpR0q5CWPSCJv9oakYhohLfM3vnU0MH7FuIQSzDUiB%2FxlsUeyu%2Fem1XRVuZVI4eBNoYZFszXJ6jgRnZKXXgj%2BHX5jFqRXjSic%2FgPJkeQPrKJx3ixpx1ZOePWwGg4u3jawMT%2BEBvC6ZHsznTasp6FdkTj09t3foYuCPDA%2BCy3Qagq1lQA0D8f7G1B62HPs4fiww%2FI9gm%2FI%2B2M4cBosO4EUsYb1ODvexrx62fWbBh68bbiz9Dcacpn9CYAckAAAAAElFTkSuQmCC&logoColor=white"></a>
  <a href="https://github.com/AdrianNeshad/CryptoToolbox/releases/download/v2.8/Verktygsladan2.8.exe"><img alt="Ladda ner Windows-app (Verktygsladan2.8.exe)" src="https://img.shields.io/badge/Windows-Verktygsladan2.8.exe-0a84ff?style=for-the-badge&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAAXNSR0IArs4c6QAAAHhlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAAGAAAAAAQAAAYAAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAABSgAwAEAAAAAQAAABQAAAAALPklgQAAAAlwSFlzAAA7DgAAOw4BzLahgwAAA9dJREFUOBGFVF1oXFUQnnPu7r0mm3QTmyabYmNabYXWPIg%2FD7YBf2NBEiw2ZhWK2RKpUEEiteCL4INIVWwJ%2BNCwNVFs0iUqtPiDhRRSfFGoYqNBCK2Joc1mgy1Jum527zln%2FM5m9zZqbYede2bOfDNnzsycFXQLakh23Std5xsmVqxVx1xiZPxmLvJmRmuTIfkquc4dwnWahZC9t8KL1YD1RzubqMrrCC2Y436U1hjNzwPwMjB3lnDT0I%2By5mE3JxdUlPZwjk7O9gxNl%2BMEAWMD8WZyxClZEW4x2cKvANSL20LrSJkydmUNSeJlNQ8lIyPuNpPzJ4wxHZnu1AULCK7MUrSXghE5cpsIyXWkmYwyl42vxooM2e4VbcDgYILPVodl%2B8ppqwKGfXXc%2FFU4LxxJAnmzocy15WzP3A8n7kk%2FcmhnuvnQzpzSLeTrfWw4YzE4mEzWH3e0%2BqQcMFQWjHQikOvJAg3P%2F7m08FShbWiJuqv7SModhIIsPPBpu6j2%2BhsHO88xhb8WkurR%2FfqS7xUbK7iykdQlvFDMppfP594otA4s0l3RUQRLALcZfJaq3CmsNNs9ck4o%2FabFos4NRtALdt%2BSiH3UuVV44V72TRtq08RKp9NfpTbxsP4QV7LBLH0B7hJCKGYOQ958e%2F9zlzzPmYDPelZmBqX61ijRJ0k6gxR2ekiKJutpmCY5MWmQWavVSzRWCmZLlAR%2FecV9N89sJpET7ik2YFZ7iPTnFsAlJ2uwYpgq7tbA5YN9ogPIzIW%2BHfwM%2BCI14zsFXkWoQBht0gl0LikMX0L3dF4tH6H7qBq4oL6QN4DfA9tguAaNibc2Ijm5pZgP8x9U0MeYdUcxJYuJDcb3L%2BtC9uqWwydpR9Nn2HrM7t%2BAfqfxzBNrv9%2F3qFcZSeIxEOf9g%2BkXU%2FbA4pAEPnx%2BupZa%2FhPsNwDsc8Ft6Du6kHnHHe2O1kVqTqNEdaxNWmp66PLeEzM2UDCHqFEt9H9ndoYmFjspt2aJ7seQvCS86PZd8bWRmreh1bGtPot5WaWyNpil4pVLwUagP17ctR%2FmM%2FTz9LM1P%2Fa2eW7FfrxpR0q5CWPSCJv9oakYhohLfM3vnU0MH7FuIQSzDUiB%2FxlsUeyu%2Fem1XRVuZVI4eBNoYZFszXJ6jgRnZKXXgj%2BHX5jFqRXjSic%2FgPJkeQPrKJx3ixpx1ZOePWwGg4u3jawMT%2BEBvC6ZHsznTasp6FdkTj09t3foYuCPDA%2BCy3Qagq1lQA0D8f7G1B62HPs4fiww%2FI9gm%2FI%2B2M4cBosO4EUsYb1ODvexrx62fWbBh68bbiz9Dcacpn9CYAckAAAAAElFTkSuQmCC&logoColor=white"></a>
</p>

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
