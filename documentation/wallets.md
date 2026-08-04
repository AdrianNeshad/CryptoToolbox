# Krypto Wallets – Lagringsmetoder

| Wallet | Plattform | Filformat | Kryptering | KDF/Lagring | Anteckning |
|---------|-----------|-----------|------------|-------------| |
| MetaMask | PC/Web | JSON Vault | AES-256-GCM | PBKDF2 / Browser Storage | support.metamask.io/configure/wallet/how-to-recover-your-secret-recovery-phrase/ |
| MetaMask | iOS/Android | JSON Vault | AES-256-GCM | Keychain/Keystore | iterations: 5000 för mobile |
| Phantom | PC/Web | JSON Vault | AES-256-GCM | PBKDF2/Keychain | Lagras i keychain med entropy som går att konvertera till mnemonic |
| Exodus | Desktop | `seed.seco` | AES-256 | PBKDF2 | github.com/AdrianNeshad/secoUnlock |
| Electrum | Desktop | `wallet` | AES-256-CBC | PBKDF2 | github.com/AdrianNeshad/electrumUnlock |
| Monero GUI | Desktop | `.keys` | ChaCha20 | Wallet password | Återställ .keys fil i moneroGUI eller featherWallet, dekrypterat men encoded lösenord går att använda som password |
| Trust Wallet | Mobile | Encrypted DB | AES-256-GCM | Keychain/Keystore | |
| Coinbase Wallet | Web/Mobile | JSON/DB | AES-256-GCM | PBKDF2/Keychain | |
| BlueWallet | Mobile | Encrypted JSON | AES-256-GCM | Keychain/Keystore | |
| Atomic | Desktop/Mobile | JSON/DB | AES-256 | PBKDF2 | |
| Guarda | Desktop/Mobile | JSON/DB | AES-256 | PBKDF2 | |
| Keplr / Leap / Brave / Rabby / Ronin / XDEFI / Solflare / Backpack | Web | JSON Vault | AES-256-GCM | PBKDF2 | |

## Exempel

### Exodus
- `seed.seco`
- `passphrase.seco`

### Monero
- `wallet.keys`

### Electrum
- `default_wallet`

### MetaMask / Phantom JSON Vault
- `ciphertext`
- `iv`
- `salt`
- `mac`

### Ethereum Keystore V3
```json
crypto {
  cipher = aes-128-ctr,
  kdf = scrypt,
  ...
}
```

```json
{
    "version": 3,
    "id": "e0fe53d0-7a3d-4f65-88b1-9bb4e245a169",
    "crypto": {
        "ciphertext": "64b5b416bb2bef882eb7cc63ed92c064e53c818ec46351e07ac140e5ba871596f1595fe6cad8333147fe68c031ba001b79b64dd1edd513043134217b7ffe1903ca23b1fbe823671827e3b2dff69bbd448d9cb79a3321ec8801f2a995",
        "cipherparams": {
            "iv": "7aaf7eb6f4b0e7d995e8eac67e4d52eb"
        },
        "kdf": "scrypt",
        "kdfparams": {
            "r": 8,
            "p": 6,
            "n": 4096,
            "dklen": 32,
            "salt": "80132842c6cde8f9d04582932ef92c3cad3ba6b41e1296ef681692372886db86"
        },
        "mac": "01816d0a5c31cd03b644f2d756ac8167c2498808040cbace8c35c46dcf06b7a1",
        "cipher": "aes-128-ctr"
    },
    "type": "mnemonic",
    "coin": 60,
    "address": "32dd55E0BCF509a35A3F5eEb8593fbEb244796b1"
}
```