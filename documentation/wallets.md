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

### Exodus
- `seed.seco`
- `passphrase.seco`

### Monero
- `wallet.keys`

### Electrum
- `default_wallet`