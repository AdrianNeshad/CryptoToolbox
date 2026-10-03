// Orchestration: turn a local iOS backup folder into decrypted keychain records.
// Mirrors the `dumpkeys` path of dunhamsteve/ios irestore, entirely in-browser.
(function () {
  'use strict';

  function le32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

  // Parse Manifest.plist -> keybag bytes, encryption flag, wrapped manifest key.
  function parseManifest(bytes) {
    var p = window.KC.bplist.parse(bytes);
    var lock = p.Lockdown || {};
    return {
      backupKeyBag: p.BackupKeyBag || null,
      isEncrypted: !!p.IsEncrypted,
      manifestKey: p.ManifestKey || null,
      deviceName: lock.DeviceName || p.DeviceName || '',
      productVersion: lock.ProductVersion || '',
      raw: p
    };
  }

  // group: array of { v_Data, v_PersistentRef }. Returns decoded records.
  function dumpKeyGroup(kb, group) {
    var KC = window.KC;
    var out = [];
    for (var i = 0; i < group.length; i++) {
      var entry = group[i];
      var data = entry['v_Data'];
      if (!data || data.length < 12) continue;
      var rec = { __ref: entry['v_PersistentRef'] || null };
      var version = le32(data, 0);
      var cls = le32(data, 4);
      if (version !== 3) {
        rec.__error = 'Unhandled keychain blob version ' + version;
        out.push(rec);
        continue;
      }
      var l = le32(data, 8);
      var wkey = data.subarray(12, 12 + l);
      var edata = data.subarray(12 + l);
      var ckey = KC.keybag.getClassKey(kb, cls);
      if (!ckey) { rec.__error = 'No key for protection class ' + cls; out.push(rec); continue; }
      var itemKey = KC.aes.keyUnwrap(ckey, wkey);
      if (!itemKey) { rec.__error = 'Key unwrap failed (class ' + cls + ')'; out.push(rec); continue; }
      var plain;
      try { plain = KC.aes.gcmBlankIvOpen(itemKey, edata); }
      catch (e) { rec.__error = 'Decrypt failed: ' + e.message; out.push(rec); continue; }
      var fields;
      try { fields = KC.asn1.parseRecord(plain); }
      catch (e) { rec.__error = 'ASN.1 parse failed: ' + e.message; out.push(rec); continue; }
      for (var k in fields) if (fields.hasOwnProperty(k)) rec[k] = fields[k];
      rec.__class = cls;
      out.push(rec);
    }
    return out;
  }

  // opts: { getBytes(relpath)->Promise<Uint8Array|null>, password, SQL, onProgress }
  async function loadKeychain(opts) {
    var KC = window.KC;
    var log = opts.onProgress || function () {};

    log('Reading Manifest.plist…');
    var manifestBytes = await opts.getBytes('Manifest.plist');
    if (!manifestBytes) throw new Error('Manifest.plist not found in the selected folder. Pick the backup folder itself (the one that contains Manifest.plist and Manifest.db).');
    var manifest = parseManifest(manifestBytes);
    if (!manifest.backupKeyBag) throw new Error('No BackupKeyBag in Manifest.plist — not a recognizable iOS backup.');

    log('Parsing keybag…');
    var kb = KC.keybag.read(manifest.backupKeyBag);

    if (manifest.isEncrypted) {
      if (!opts.password) { var e = new Error('This backup is encrypted. Enter the backup password.'); e.needsPassword = true; throw e; }
      log('Deriving keys from password…');
      await KC.keybag.setPassword(kb, opts.password); // throws 'Bad password'
    } else {
      throw new Error('This backup is not encrypted. iOS only includes the keychain in encrypted backups, so there is nothing to show. Re-create the backup with "Encrypt local backup" enabled.');
    }

    log('Reading Manifest.db…');
    var dbBytes = await opts.getBytes('Manifest.db');
    if (!dbBytes) throw new Error('Manifest.db not found in the selected folder.');

    if (manifest.manifestKey) {
      log('Decrypting Manifest.db…');
      var mk = manifest.manifestKey;
      var cls = le32(mk, 0);
      var ckey = KC.keybag.getClassKey(kb, cls);
      if (!ckey) throw new Error('No manifest key for class ' + cls + ' (wrong password?).');
      var mkey = KC.aes.keyUnwrap(ckey, mk.subarray(4));
      if (!mkey) throw new Error('Could not unwrap the manifest key (wrong password?).');
      dbBytes = KC.aes.cbcDecrypt(mkey, dbBytes); // raw CBC, no padding removal
    }

    log('Opening manifest database…');
    var db = new opts.SQL.Database(dbBytes);
    var rows;
    try {
      rows = db.exec("SELECT fileID, file FROM Files WHERE domain='KeychainDomain' AND relativePath='keychain-backup.plist'");
    } catch (err) {
      db.close();
      throw new Error('Could not read the manifest database (wrong password?): ' + err.message);
    }
    if (!rows.length || !rows[0].values.length) {
      // fallback: any keychain-backup.plist
      try { rows = db.exec("SELECT fileID, file FROM Files WHERE relativePath LIKE '%keychain-backup.plist'"); } catch (e2) {}
    }
    if (!rows.length || !rows[0].values.length) {
      db.close();
      throw new Error('No keychain-backup.plist entry found in this backup.');
    }
    var fileID = rows[0].values[0][0];
    var blob = rows[0].values[0][1]; // Uint8Array
    db.close();

    log('Resolving keychain file key…');
    var fileRec = KC.nskeyed.unarchive(KC.bplist.parse(blob instanceof Uint8Array ? blob : new Uint8Array(blob)));
    var encKey = fileRec.EncryptionKey;
    var protClass = fileRec.ProtectionClass;
    if (!(encKey instanceof Uint8Array)) throw new Error('Keychain file record has no EncryptionKey.');
    var classKey = KC.keybag.getClassKey(kb, protClass);
    if (!classKey) throw new Error('No key for keychain file protection class ' + protClass + '.');
    var fileKey = KC.aes.keyUnwrap(classKey, encKey.subarray(4));
    if (!fileKey) throw new Error('Could not unwrap the keychain file key.');

    log('Reading keychain-backup.plist…');
    var kcBytes = await readById(opts.getBytes, fileID);
    if (!kcBytes) throw new Error('Keychain file (' + fileID + ') not found on disk in the selected folder.');
    var kcPlain = KC.aes.unpadPkcs7(KC.aes.cbcDecrypt(fileKey, kcBytes));
    if (!kcPlain) throw new Error('Keychain file decryption failed (bad padding).');

    log('Decoding keychain entries…');
    var kc = KC.bplist.parse(kcPlain);
    var result = {
      deviceName: manifest.deviceName,
      productVersion: manifest.productVersion,
      General: dumpKeyGroup(kb, kc.genp || []),
      Internet: dumpKeyGroup(kb, kc.inet || []),
      Certs: dumpKeyGroup(kb, kc.cert || []),
      Keys: dumpKeyGroup(kb, kc.keys || [])
    };
    return result;
  }

  async function readById(getBytes, id) {
    var b = await getBytes(id);
    if (b) return b;
    if (id && id.length >= 2) return await getBytes(id.slice(0, 2) + '/' + id);
    return null;
  }

  window.KC = window.KC || {};
  window.KC.backup = { parseManifest: parseManifest, loadKeychain: loadKeychain, dumpKeyGroup: dumpKeyGroup };
})();
