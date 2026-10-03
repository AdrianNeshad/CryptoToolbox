// iOS backup keybag: TLV parser, password derivation, class-key unwrap.
// Ported from dunhamsteve/ios keybag.go. PBKDF2 uses WebCrypto (fast, native);
// the RFC 3394 unwrap uses the pure-JS AES in aes.js.
(function () {
  'use strict';

  function be32(b, o) { return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; }

  // Parse a raw keybag blob into { version, type, wrap, salt, iter, auxSalt,
  // auxIter, uuid, keys: [{uuid, class, wrap, keyType, wrappedKey, key}] }.
  function read(data) {
    var kb = { keys: [], salt: null, iter: 0, auxSalt: null, auxIter: 0, wrap: 0 };
    var key = null;
    var state = 0;
    for (var pos = 0; pos + 8 <= data.length;) {
      var fourcc = String.fromCharCode(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
      var size = be32(data, pos + 4);
      pos += 8;
      var value = data.subarray(pos, pos + size);
      var ivalue = size === 4 ? be32(data, pos) : 0;
      pos += size;

      if (state < 2) {
        switch (fourcc) {
          case 'VERS': kb.version = ivalue; break;
          case 'TYPE': kb.type = ivalue; break;
          case 'WRAP': kb.wrap = ivalue; break;
          case 'HMCK': kb.hmac = value; break;
          case 'SALT': kb.salt = value; break;
          case 'ITER': kb.iter = ivalue; break;
          case 'DPWT': break;
          case 'DPIC': kb.auxIter = ivalue; break;
          case 'DPSL': kb.auxSalt = value; break;
          case 'UUID':
            state++;
            if (state === 2) { pos -= 8 + size; } // rewind: first per-key UUID
            else { kb.uuid = value; }
            break;
          default: break; // tolerate unknown top-matter tags
        }
      } else {
        switch (fourcc) {
          case 'UUID': key = { class: 0, wrap: 0, keyType: 0 }; kb.keys.push(key); key.uuid = value; break;
          case 'CLAS': key.class = ivalue; break;
          case 'WRAP': key.wrap = ivalue; break;
          case 'KTYP': key.keyType = ivalue; break;
          case 'WPKY': key.wrappedKey = value; break;
          default: break;
        }
      }
    }
    return kb;
  }

  async function pbkdf2(pw, salt, iters, hash, dkLenBytes) {
    var base = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: iters, hash: hash }, base, dkLenBytes * 8);
    return new Uint8Array(bits);
  }

  function hexToBytes(h) { return Uint8Array.from(h.match(/../g).map(function (x) { return parseInt(x, 16); })); }

  // Decrypt the keybag with the backup password, recovering class keys.
  // Returns true on success, throws Error('Bad password') on failure.
  async function setPassword(kb, password) {
    var passkey;
    if (password.length === 64 && /^[0-9a-fA-F]{64}$/.test(password)) {
      passkey = hexToBytes(password);
    } else {
      passkey = new TextEncoder().encode(password);
      if (kb.auxIter > 0) {
        passkey = await pbkdf2(passkey, kb.auxSalt, kb.auxIter, 'SHA-256', 32);
      }
      passkey = await pbkdf2(passkey, kb.salt, kb.iter, 'SHA-1', 32);
    }
    var unwrap = window.KC.aes.keyUnwrap;
    for (var i = 0; i < kb.keys.length; i++) {
      var k = kb.keys[i];
      if (k.wrap === 2) { // 2: wrapped with passcode key only
        k.key = unwrap(passkey, k.wrappedKey);
        if (!k.key) throw new Error('Bad password');
      }
    }
    kb._passkey = passkey;
    return true;
  }

  function getClassKey(kb, cls) {
    for (var i = 0; i < kb.keys.length; i++) {
      if (kb.keys[i].class === cls && kb.keys[i].key) return kb.keys[i].key;
    }
    return null;
  }

  window.KC = window.KC || {};
  window.KC.keybag = { read: read, setPassword: setPassword, getClassKey: getClassKey };
})();
