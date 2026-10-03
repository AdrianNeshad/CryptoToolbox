# Sample backup

`sample-backup/` is a **synthetic, fully fake** encrypted iOS backup for trying out
the iOS Keychain Viewer without a real device backup. All data is invented.

To use it:

1. Open the **iOS Keychain Viewer** tool.
2. **Choose folder** → select the `sample-backup` folder.
3. Enter the backup password from `password.txt` (`demo-pass-123`).
4. Click **Open keychain**.

You should see 3 generic passwords and 2 internet passwords (a demo email login,
a Wi-Fi password, an app token, a GitHub token and an IMAP login).

## How it was made

The fixture is generated with the same crypto an iPhone uses, so it exercises the
whole pipeline: a PBKDF2/AES keybag, an AES-CBC–encrypted `Manifest.db` (SQLite),
an `NSKeyedArchiver` file record, and the AES-key-wrapped, GCM-encrypted keychain
items. The keychain file is stored under the `xx/<fileID>` sub-folder layout that
newer backups use. Nothing here comes from a real account.
