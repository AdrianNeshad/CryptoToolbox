# Proton Wallet recovery — tests

Known-answer tests for the decryption pipeline. Fully offline; uses only the
vendored OpenPGP build and the tool's own pure-JS AES-GCM.

```bash
node tools/protonWallet/test/node-test.cjs
```

## What is covered

| Test | Source of the vector |
|------|----------------------|
| AES-256-GCM decrypts & authenticates `"Hello AES-256-GCM"` | `rust/src/proton_wallet/crypto/wallet_key.rs` (`test_decryption`) |
| `user_2` / `user_3` wallet-key PGP message → the same 32-byte AES key, then mnemonic | `rust/src/mocks/user_keys.rs` + `test_unlock_wallet_key*` |
| JSON keychain format (`proton_wallet_k_provider_key` / `..._mn_provider_key`) matched by `walletId` | app providers |
| Legacy format (PGP-wrapped base64 AES-GCM blob) | `wallet.mnemonic.provider.dart` legacy branch |
| Wrong passphrase fails cleanly | — |

The two PGP vectors are real GopenPGP/ProtonMail output taken verbatim from the
Proton Wallet app's own Rust unit tests, so a pass proves byte-exact
compatibility with how the app encrypts, not just an internal round-trip.

The `user_2` key is locked with the passphrase `password`; `user_3` with the
already-derived key secret `4sFlJ8gesYLeYyS0cBFQ5biAZPIZyHe` — the same kind of
value the keychain stores under `userPassphrase`.
