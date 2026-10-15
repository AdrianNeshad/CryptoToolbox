// Proton Wallet mnemonic recovery — offline decryption logic.
//
// Chain (from the Proton Wallet flutter app, lib/managers/providers/*):
//   userPassphrase  unlocks  userPrivateKey (OpenPGP)
//   walletKey (PGP message)  --PGP decrypt-->  32-byte AES-256 key
//   mnemonic (base64 IV|ct|tag)  --AES-256-GCM-->  BIP39 mnemonic
//
// Variants supported:
//   A "modern"  : mnemonic = base64(AES-256-GCM(walletKey, phrase))
//   B "legacy"  : mnemonic = PGP(userKeys) wrapping the base64 AES-GCM blob
//   C "pgp-only": mnemonic = PGP(userKeys) wrapping the plain phrase
//
// Uses vendored openpgp.js (window.openpgp) + pure-JS AES-GCM (window.ProtonAESGCM).
(function () {
  'use strict';

  var BIP39_COUNTS = { 12: 1, 15: 1, 18: 1, 21: 1, 24: 1 };

  // Keychain / JSON dumps usually store these values with the newlines escaped
  // as literal "\n" and the whole string wrapped in quotes. OpenPGP's armor
  // parser needs real newlines, so normalize before parsing.
  //
  // IMPORTANT: unescaping must never touch a JSON envelope — valid JSON legally
  // carries "\n" inside string literals, and turning those into raw newlines
  // would make it unparseable. So unescape only armored/base64 text and the
  // individual string VALUES pulled out of JSON, not the JSON wrapper itself.

  function stripQuotes(text) {
    var t = String(text).trim();
    if (t.length >= 2 &&
      ((t.charAt(0) === '"' && t.charAt(t.length - 1) === '"') ||
       (t.charAt(0) === "'" && t.charAt(t.length - 1) === "'"))) {
      t = t.slice(1, -1);
    }
    return t;
  }

  // Un-escape \n \r \t in a single armored/base64 value. Base64 and armor never
  // contain a backslash, so this is a no-op on a clean paste.
  function unescapeValue(text) {
    var t = stripQuotes(text);
    if (t.indexOf('\\n') >= 0 || t.indexOf('\\r') >= 0 || t.indexOf('\\t') >= 0) {
      t = t.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n')
        .replace(/\\r/g, '\n').replace(/\\t/g, '\t');
    }
    return t;
  }

  function b64ToBytes(b64) {
    var clean = String(b64).replace(/\s+/g, '');
    var bin = atob(clean);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToUtf8(bytes) {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    }
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    try { return decodeURIComponent(escape(s)); } catch (e) { return s; }
  }

  function looksLikeMnemonic(text) {
    if (!text) return false;
    var words = text.trim().split(/\s+/);
    if (!BIP39_COUNTS[words.length]) return false;
    for (var i = 0; i < words.length; i++) {
      if (!/^[a-z]+$/.test(words[i])) return false;
    }
    return true;
  }

  // Split a textarea that may hold one or more armored PGP blocks.
  function splitArmored(text, type) {
    var re = new RegExp('-----BEGIN PGP ' + type + '-----[\\s\\S]*?-----END PGP ' + type + '-----', 'g');
    return text.match(re) || [];
  }

  // Accepts: a JSON array of {walletId,userKeyId,walletKey,walletKeySignature}
  // (the proton_wallet_k_provider_key value), or one raw armored PGP MESSAGE.
  function parseWalletKeys(text) {
    var trimmed = stripQuotes(text);
    if (!trimmed) return [];
    if (trimmed[0] === '[' || trimmed[0] === '{') {
      var data = JSON.parse(trimmed);
      if (!Array.isArray(data)) data = [data];
      return data.map(function (o) {
        return {
          walletId: o.walletId || o.walletID || o.WalletID || null,
          userKeyId: o.userKeyId || o.UserKeyID || null,
          walletKey: unescapeValue(o.walletKey || o.WalletKey || ''),
          signature: unescapeValue(o.walletKeySignature || o.WalletKeySignature || ''),
        };
      });
    }
    var msgs = splitArmored(unescapeValue(trimmed), 'MESSAGE');
    return msgs.map(function (m) {
      return { walletId: null, userKeyId: null, walletKey: m, signature: null };
    });
  }

  // Accepts: a JSON array of {walletID,mnemonic} (proton_wallet_mn_provider_key),
  // or one raw base64 blob / one armored PGP MESSAGE.
  function parseMnemonics(text) {
    var trimmed = stripQuotes(text);
    if (!trimmed) return [];
    if (trimmed[0] === '[' || trimmed[0] === '{') {
      var data = JSON.parse(trimmed);
      if (!Array.isArray(data)) data = [data];
      return data.map(function (o) {
        return {
          walletId: o.walletID || o.walletId || o.WalletID || null,
          mnemonic: unescapeValue(o.mnemonic || o.Mnemonic || ''),
        };
      });
    }
    return [{ walletId: null, mnemonic: unescapeValue(trimmed) }];
  }

  function matchMnemonic(mnemonics, walletId, index) {
    if (walletId) {
      for (var i = 0; i < mnemonics.length; i++) {
        if (mnemonics[i].walletId === walletId) return mnemonics[i];
      }
    }
    // fall back to positional match when ids are absent
    if (mnemonics.length === 1) return mnemonics[0];
    return mnemonics[index] || null;
  }

  async function readPrivateKeys(armoredList, passphrase, log) {
    var unlocked = [];
    for (var i = 0; i < armoredList.length; i++) {
      var key;
      try {
        key = await openpgp.readPrivateKey({ armoredKey: armoredList[i] });
      } catch (e) {
        log('Could not parse user key #' + (i + 1) + ': ' + e.message);
        continue;
      }
      if (!key.isDecrypted()) {
        try {
          key = await openpgp.decryptKey({ privateKey: key, passphrase: passphrase });
        } catch (e) {
          log('Could not unlock user key #' + (i + 1) + ' with the passphrase: ' + e.message);
          continue;
        }
      }
      unlocked.push(key);
    }
    return unlocked;
  }

  async function pgpDecryptToBytes(armoredMessage, keys) {
    var message = await openpgp.readMessage({ armoredMessage: armoredMessage });
    var res = await openpgp.decrypt({
      message: message,
      decryptionKeys: keys,
      format: 'binary',
      config: { allowInsecureDecryptionWithSigningKeys: true },
    });
    return res.data instanceof Uint8Array ? res.data : new Uint8Array(res.data);
  }

  // Try to decrypt one wallet key (PGP message) -> 32-byte AES key.
  async function unlockWalletKey(armoredWalletKey, keys) {
    var bytes = await pgpDecryptToBytes(armoredWalletKey, keys);
    if (bytes.length !== 32) {
      throw new Error('decrypted wallet key is ' + bytes.length + ' bytes, expected 32');
    }
    return bytes;
  }

  async function recoverMnemonic(encryptedMnemonic, walletKey, userKeys) {
    var warnings = [];

    // Strategy A: modern — base64 blob, AES-256-GCM with the wallet key.
    try {
      var blob = b64ToBytes(encryptedMnemonic);
      var a = window.ProtonAESGCM.gcmOpen(walletKey, blob);
      var textA = bytesToUtf8(a.plaintext);
      if (a.authentic) {
        return { mnemonic: textA, method: 'modern (AES-256-GCM)', authentic: true,
          valid: looksLikeMnemonic(textA), warnings: warnings };
      }
    } catch (e) { /* fall through */ }

    // Strategy B: legacy — PGP-wrapped base64 AES-GCM blob.
    try {
      var inner = bytesToUtf8(await pgpDecryptToBytes(encryptedMnemonic, userKeys));
      var blobB = b64ToBytes(inner);
      var b = window.ProtonAESGCM.gcmOpen(walletKey, blobB);
      var textB = bytesToUtf8(b.plaintext);
      if (b.authentic) {
        return { mnemonic: textB, method: 'legacy (PGP + AES-256-GCM)', authentic: true,
          valid: looksLikeMnemonic(textB), warnings: warnings };
      }
    } catch (e) { /* fall through */ }

    // Strategy C: oldest — PGP wrapping the plain phrase.
    try {
      var textC = bytesToUtf8(await pgpDecryptToBytes(encryptedMnemonic, userKeys));
      if (looksLikeMnemonic(textC)) {
        return { mnemonic: textC, method: 'pgp-only', authentic: true, valid: true, warnings: warnings };
      }
      // last resort: return whatever modern produced even if tag failed? No — report failure.
    } catch (e) { /* fall through */ }

    throw new Error('none of the known Proton mnemonic formats decrypted successfully');
  }

  // opts: { userKeysText, passphrase, walletKeysText, mnemonicsText, onLog }
  async function decryptAll(opts) {
    var log = opts.onLog || function () {};
    if (typeof openpgp === 'undefined') throw new Error('OpenPGP library not loaded');
    if (!window.ProtonAESGCM) throw new Error('AES-GCM module not loaded');

    var armoredKeys = splitArmored(unescapeValue(opts.userKeysText || ''), 'PRIVATE KEY BLOCK');
    if (!armoredKeys.length) throw new Error('No user PGP private key found. Paste the "userPrivateKey" block.');

    var walletKeys = parseWalletKeys(opts.walletKeysText || '');
    if (!walletKeys.length) throw new Error('No wallet key found. Paste "proton_wallet_k_provider_key".');

    var mnemonics = parseMnemonics(opts.mnemonicsText || '');
    if (!mnemonics.length) throw new Error('No encrypted mnemonic found. Paste "proton_wallet_mn_provider_key".');

    log('Unlocking ' + armoredKeys.length + ' user key(s) with the passphrase…');
    var userKeys = await readPrivateKeys(armoredKeys, opts.passphrase || '', log);
    if (!userKeys.length) throw new Error('Could not unlock any user key. Check the passphrase (userPassphrase).');
    log('Unlocked ' + userKeys.length + ' user key(s).');

    var results = [];
    for (var i = 0; i < walletKeys.length; i++) {
      var wk = walletKeys[i];
      var label = wk.walletId || ('wallet #' + (i + 1));
      var entry = { walletId: wk.walletId, label: label };
      try {
        log('[' + label + '] decrypting wallet key…');
        var aesKey = await unlockWalletKey(wk.walletKey, userKeys);
        var mn = matchMnemonic(mnemonics, wk.walletId, i);
        if (!mn || !mn.mnemonic) throw new Error('no matching encrypted mnemonic for this wallet');
        log('[' + label + '] decrypting mnemonic…');
        var rec = await recoverMnemonic(mn.mnemonic, aesKey, userKeys);
        entry.mnemonic = rec.mnemonic;
        entry.method = rec.method;
        entry.valid = rec.valid;
        entry.ok = true;
        log('[' + label + '] OK (' + rec.method + ')' + (rec.valid ? '' : ' — output does not look like a BIP39 phrase'));
      } catch (e) {
        entry.ok = false;
        entry.error = e.message;
        log('[' + label + '] FAILED: ' + e.message);
      }
      results.push(entry);
    }
    return results;
  }

  window.ProtonWallet = {
    decryptAll: decryptAll,
    parseWalletKeys: parseWalletKeys,
    parseMnemonics: parseMnemonics,
    looksLikeMnemonic: looksLikeMnemonic,
  };
})();
