# Security Policy

Crypto Toolbox is a **fully local, offline** toolbox for cryptography and crypto
forensics. It is built to handle sensitive data — seed phrases, private keys, and
wallet files — entirely on your own machine, with no network requests, no telemetry,
and nothing ever leaving the tool.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report it privately instead:

- **Preferred:** open a private report via the repo's **Security → Report a vulnerability**
  tab ([GitHub Security Advisories](https://github.com/AdrianNeshad/CryptoToolbox/security/advisories/new)).

## Using the toolbox safely

Because this app decrypts and displays secrets:

- **Run it offline.** The app never needs the internet. When working with real keys,
  use it on an offline / air-gapped machine and confirm it makes no network requests.
- **Keep it local.** Only paste real seed phrases or private keys into the Electron app,
  the Chrome extension, or a local copy of `Toolbox.html` — never into an online/hosted
  copy.
- **Nothing is uploaded.** All decryption and brute-forcing runs on your machine, in your
  browser or Electron; no keys or files are sent anywhere.
- **Clear your clipboard.** The copy buttons place secrets on your clipboard. After you're done, clear your clipboard history so keys and seeds aren't left behind.