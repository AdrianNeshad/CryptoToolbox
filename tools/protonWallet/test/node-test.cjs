#!/usr/bin/env node
/*
 * Known-answer tests for the Proton Wallet recovery tool.
 * Runs fully offline against the vendored OpenPGP build and the pure-JS AES-GCM.
 *
 *   node tools/protonWallet/test/node-test.cjs
 *
 * Vectors are taken verbatim from the Proton Wallet flutter app's own Rust unit
 * tests (rust/src/proton_wallet/crypto/wallet_key.rs and mocks/user_keys.rs):
 *   - two user keys whose wallet-key PGP message decrypts to the same 32 bytes
 *   - the AES-256-GCM "Hello AES-256-GCM" vector
 * plus a round-trip "modern" mnemonic encrypted with that recovered key.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TOOL = path.resolve(__dirname, '..');

// --- load the vendored (global-var) OpenPGP build into this realm ----------
// Indirect eval runs the bundle at global scope, so its top-level `var openpgp`
// becomes a real global, exactly as a browser <script> tag would make it.
(function loadOpenpgp() {
  const code = fs.readFileSync(path.join(TOOL, 'vendor/openpgp/openpgp.min.js'), 'utf8');
  const indirectEval = eval;
  global.openpgp = indirectEval(code + '\n;openpgp');
})();

global.window = global;
require(path.join(TOOL, 'lib/aesgcm.js'));
require(path.join(TOOL, 'lib/proton-decrypt.js'));

const EXPECTED32 = [239, 203, 93, 93, 253, 145, 50, 82, 227, 145, 154, 177, 206, 86, 83, 32,
  251, 160, 160, 29, 164, 144, 177, 101, 205, 128, 169, 38, 59, 33, 146, 218];

const USER2_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: ProtonMail\n\nxYYEZXrEuBYJKwYBBAHaRw8BAQdAd3SP+S82mvNYec99IYXXy02QlEtWOwCX\nG+VRoWMTJgT+CQMIAuL1Bl1uoZBgAAAAAAAAAAAAAAAAAAAAAP8Kb+34nsOQ\njVlCUF4Rco6I2xectxdUsuCm6X+Emq+S+8JsPw/rwVxAmClvKJaeWIfZIV/u\nyc07bm90X2Zvcl9lbWFpbF91c2VAZG9tYWluLnRsZCA8bm90X2Zvcl9lbWFp\nbF91c2VAZG9tYWluLnRsZD7CjAQQFgoAPgWCZXrEuAQLCQcICZD98eusToQD\nawMVCAoEFgACAQIZAQKbAwIeARYhBMZ9T6whFVji9dBihP3x66xOhANrAADW\n1QEA4TDQcWcCskhIbAyLj3eFN9oO4cAv01QnTYuW5p5LvMYA/AyngETI6OGC\n+/8UR3hKvmZMnThBMRfbzqg5B96KTIcBx4sEZXrEuBIKKwYBBAGXVQEFAQEH\nQCmW61ll1IgTcm8TuNuh92qEGoIzYrRs0fb6ivPBz7YJAwEIB/4JAwh2VqMV\n7EJ4WmAAAAAAAAAAAAAAAAAAAAAAjDFyvMguSeKDXNNvviwSK+nf7uqvbUNJ\nEEuxjr48kR2A6Cc4OavQJbAAHIVwUG8UQ+PYW/PvwngEGBYKACoFgmV6xLgJ\nkP3x66xOhANrApsMFiEExn1PrCEVWOL10GKE/fHrrE6EA2sAAIGYAQCzpA2U\nR18gbFL3k6xUaUaRHxZoxBZQ2crLRO1GhgxTxQEAhYFyb7k/0S4XwcDpSgJO\nYJWp7nLYBj9YSh4+qOa/5QM=\n-----END PGP PRIVATE KEY BLOCK-----\n";
const USER2_PW = "password";
const USER2_WK = "-----BEGIN PGP MESSAGE-----\n\nwV4DcsIsGT18EWcSAQdA470+uQXoFiWdZpCsAEgbMdjJRCjMqszNbtJQzvszrWEw\na/SJbREBGGix0byD0wz1OXHCDHHDuk42xpaXdK+16Q8aL3qYdDvL3o2foUTkR+sQ\n0lEB8m4dH4rLSeb/XPO3vFrFWhNTo6HEqsi2LDjxc+Ht3ZxZSsl0ajFDgr2OV+O1\nnNq7hTKrnwMd1DknxUcykvvLzwnVgPPKTKeivJboCQChpOc=\n=Po8E\n-----END PGP MESSAGE-----\n";

const USER3_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: ProtonMail\n\nxYYEZcHI+hYJKwYBBAHaRw8BAQdAP95X+OxFf4BIZ6pVof0uGieuTrnlpxOn\n07kbnarFd9n+CQMIbH/7cYVS4IJg2yUdFVTAyfaM0gVEeMzGCM8+ZUPe6/qF\nAsMkTKFXYSvwwsjw/NwmCGxUGRlbOQilIHhrxRcgNnVZWM9vs+xlt1CUGRJL\nNM07bm90X2Zvcl9lbWFpbF91c2VAZG9tYWluLnRsZCA8bm90X2Zvcl9lbWFp\nbF91c2VAZG9tYWluLnRsZD7CjAQQFgoAPgWCZcHI+gQLCQcICZC3N9EM+mvd\nVwMVCAoEFgACAQIZAQKbAwIeARYhBOkPJufu+pzcnwymRLc30Qz6a91XAAAL\n6wD9EMH2oS2Eud7JNoslh8xWac9bT15sUUmGBgwMSWxfyW8A/jb7ubVOBoQv\nl0FQpevuWScbCwsNXI97l7j623a+f54Px4sEZcHI+hIKKwYBBAGXVQEFAQEH\nQLEg5FwJpuFkUcZlNwrgUL8pqm6tQP5H03kHrlEaRUZpAwEIB/4JAwhObU5t\nfQYriWAIzA7e3ZNHBa4Q2LHwxZUz3ACTwua2SXZ5OxD0Io4jFkxiTuETIOnl\nLFQzHg+VVXcdEno56hjnsqHFFB7M94bsNjIImFoNwngEGBYKACoFgmXByPoJ\nkLc30Qz6a91XApsMFiEE6Q8m5+76nNyfDKZEtzfRDPpr3VcAAAQ2AQCQOIGC\nyNzZ8VU8OLu4uKi/U/uQBUcvW5z8W/QkfMiFCwEAm35gvMJB1ScmKCFJNI0t\nPguJGsxgNW6mwkszNjYfCQY=\n=xVXK\n-----END PGP PRIVATE KEY BLOCK-----\n";
const USER3_PW = "4sFlJ8gesYLeYyS0cBFQ5biAZPIZyHe";
const USER3_WK = "-----BEGIN PGP MESSAGE-----\nComment: https://gopenpgp.org\nVersion: GopenPGP 2.7.5\n\nwV4D9Oug9vT13XESAQdAQkDaJMVbFk5TQ2XmK6qZU4rKVLV1DIccP11ljsbkqRgw\n/D/q1wGge0x3vPAAqjzRcMK7hyeIP9LCMfvjkBdS6o6E7CAROpAD7crqqHXtWt5W\n0lEBEPnoASMJSW9sPjmCzOz7OsDgXvTDefYrS8sp40y+4XVKs30m8q2oXIVYEZC6\nRK1A5P738mJ0y+chA2IOVWaLdOROM6O33lX+N8jfdsz5S+c=\n=yEP9\n-----END PGP MESSAGE-----\n";

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name); }
}

function encModern(keyBytes, text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(keyBytes), iv);
  const ct = Buffer.concat([c.update(Buffer.from(text, 'utf8')), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]).toString('base64');
}

(async () => {
  // 1) AES-256-GCM known-answer vector (independent of PGP)
  {
    const key = new Uint8Array(Buffer.from('MmI0OGRmZjQ2YzNhN2YyYmQ2NjFlNWEzNzljYTQwZGQ=', 'base64'));
    const blob = new Uint8Array(Buffer.from('dTb2Z1bsWkpo2TTCWOK09tanO3n5Ipepbj5WlCRZSuvlkEAxfePeUBCu4Qo6', 'base64'));
    const r = window.ProtonAESGCM.gcmOpen(key, blob);
    const txt = Buffer.from(r.plaintext).toString('utf8');
    check('AES-256-GCM vector decrypts & authenticates', r.authentic && txt === 'Hello AES-256-GCM');
  }

  // 2) PGP wallet-key vectors -> 32-byte AES key (via full orchestration, modern mnemonic)
  for (const [name, key, pw, wk] of [['user_2', USER2_KEY, USER2_PW, USER2_WK], ['user_3', USER3_KEY, USER3_PW, USER3_WK]]) {
    const phrase = 'benefit indoor helmet wine exist height grain spot rely half beef nothing';
    const mn = encModern(EXPECTED32, phrase);
    const res = await window.ProtonWallet.decryptAll({
      userKeysText: key, passphrase: pw, walletKeysText: wk, mnemonicsText: mn, onLog: () => {},
    });
    check(name + ': wallet key unlocks and mnemonic recovers (modern)',
      res[0] && res[0].ok && res[0].mnemonic === phrase && res[0].method.indexOf('modern') === 0);
  }

  // 3) JSON keychain format + positional/id matching
  {
    const phrase = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
    const mn = encModern(EXPECTED32, phrase);
    const kJson = JSON.stringify([{ walletId: 'w1', userKeyId: 'u1', walletKey: USER3_WK, walletKeySignature: '' }]);
    const mJson = JSON.stringify([{ walletID: 'w1', mnemonic: mn }]);
    const res = await window.ProtonWallet.decryptAll({
      userKeysText: USER3_KEY, passphrase: USER3_PW, walletKeysText: kJson, mnemonicsText: mJson, onLog: () => {},
    });
    check('JSON keychain format matches by walletId', res[0] && res[0].ok && res[0].walletId === 'w1' && res[0].mnemonic === phrase);
  }

  // 4) Legacy format (PGP-wrapped base64 AES-GCM blob)
  {
    const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const mn = encModern(EXPECTED32, phrase);
    const pub = await openpgp.readKey({ armoredKey: USER3_KEY });
    const legacy = await openpgp.encrypt({ message: await openpgp.createMessage({ text: mn }), encryptionKeys: pub, format: 'armored' });
    const res = await window.ProtonWallet.decryptAll({
      userKeysText: USER3_KEY, passphrase: USER3_PW, walletKeysText: USER3_WK, mnemonicsText: legacy, onLog: () => {},
    });
    check('legacy PGP-wrapped format recovers', res[0] && res[0].ok && res[0].mnemonic === phrase && res[0].method.indexOf('legacy') === 0);
  }

  // 5) Wrong passphrase fails cleanly
  {
    let threw = false;
    try {
      await window.ProtonWallet.decryptAll({ userKeysText: USER3_KEY, passphrase: 'nope', walletKeysText: USER3_WK, mnemonicsText: 'AAAA', onLog: () => {} });
    } catch (e) { threw = true; }
    check('wrong passphrase rejected', threw);
  }

  // 6) Escaped input as it comes from a keychain / JSON dump:
  //    literal \n and wrapping quotes on the key; escaped newlines inside JSON strings.
  {
    const phrase = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
    const mn = encModern(EXPECTED32, phrase);
    const escKey = '"' + USER3_KEY.replace(/\n/g, '\\n') + '"';
    const escWk = USER3_WK.replace(/\n/g, '\\n'); // single PGP MESSAGE, escaped
    const res = await window.ProtonWallet.decryptAll({
      userKeysText: escKey, passphrase: USER3_PW, walletKeysText: escWk, mnemonicsText: mn, onLog: () => {},
    });
    check('escaped keychain/JSON input (\\n + quotes) is normalized', res[0] && res[0].ok && res[0].mnemonic === phrase);
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(1); });
