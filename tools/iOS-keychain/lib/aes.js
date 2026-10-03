// Pure-JS AES (T-table) + CBC / CTR / RFC 3394 key-unwrap.
//
// Everything the iOS Keychain Viewer needs runs locally in the browser with no
// network and no WebAssembly for the AES parts. WebCrypto is only used for
// PBKDF2 and SHA-1 (see keybag.js / backup.js); it is not used here because its
// AES-CBC always applies/validates PKCS#7 padding, while iOS backups need raw
// CBC (Manifest.db has no padding) and a non-standard GCM with a blank IV.
//
// AES correctness is verified against FIPS-197 / RFC test vectors in test/.
(function () {
  'use strict';

  // ---- S-box / inverse S-box ------------------------------------------------
  var sbox = new Uint8Array(256);
  var inv = new Uint8Array(256);
  (function () {
    var p = 1, q = 1;
    do {
      // multiply p by 3 in GF(2^8)
      p = p ^ (p << 1) ^ (p & 0x80 ? 0x11b : 0);
      p &= 0xff;
      // divide q by 3
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      var x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^
              ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
      x = (x ^ 0x63) & 0xff;
      sbox[p] = x;
      inv[x] = p;
    } while (p !== 1);
    sbox[0] = 0x63;
    inv[0x63] = 0;
  })();

  function xtime(a) { return ((a << 1) ^ (a & 0x80 ? 0x11b : 0)) & 0xff; }
  function mul(a, b) {
    var r = 0;
    while (b) {
      if (b & 1) r ^= a;
      a = xtime(a);
      b >>= 1;
    }
    return r & 0xff;
  }

  // ---- T-tables -------------------------------------------------------------
  var Te0 = new Uint32Array(256), Te1 = new Uint32Array(256),
      Te2 = new Uint32Array(256), Te3 = new Uint32Array(256);
  var Td0 = new Uint32Array(256), Td1 = new Uint32Array(256),
      Td2 = new Uint32Array(256), Td3 = new Uint32Array(256);
  (function () {
    for (var i = 0; i < 256; i++) {
      var s = sbox[i];
      var s2 = xtime(s), s3 = s2 ^ s;
      var t = ((s2 << 24) | (s << 16) | (s << 8) | s3) >>> 0;
      Te0[i] = t;
      Te1[i] = ((t >>> 8) | (t << 24)) >>> 0;
      Te2[i] = ((t >>> 16) | (t << 16)) >>> 0;
      Te3[i] = ((t >>> 24) | (t << 8)) >>> 0;

      var si = inv[i];
      var e = mul(si, 14), n = mul(si, 9), d = mul(si, 13), b = mul(si, 11);
      var u = ((e << 24) | (n << 16) | (d << 8) | b) >>> 0;
      Td0[i] = u;
      Td1[i] = ((u >>> 8) | (u << 24)) >>> 0;
      Td2[i] = ((u >>> 16) | (u << 16)) >>> 0;
      Td3[i] = ((u >>> 24) | (u << 8)) >>> 0;
    }
  })();

  var rcon = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
              0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000];

  function b2w(bytes, i) {
    return ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
  }

  // AES cipher instance. key: Uint8Array of 16/24/32 bytes.
  function AES(key) {
    if (!(this instanceof AES)) return new AES(key);
    var Nk = key.length / 4;
    if (Nk !== 4 && Nk !== 6 && Nk !== 8) throw new Error('AES: bad key length ' + key.length);
    var Nr = Nk + 6;
    this.rounds = Nr;
    var w = new Uint32Array(4 * (Nr + 1));
    var i;
    for (i = 0; i < Nk; i++) w[i] = b2w(key, 4 * i);
    for (i = Nk; i < w.length; i++) {
      var tmp = w[i - 1];
      if (i % Nk === 0) {
        tmp = ((tmp << 8) | (tmp >>> 24)) >>> 0; // RotWord
        tmp = ((sbox[(tmp >>> 24) & 0xff] << 24) | (sbox[(tmp >>> 16) & 0xff] << 16) |
               (sbox[(tmp >>> 8) & 0xff] << 8) | sbox[tmp & 0xff]) >>> 0;
        tmp = (tmp ^ rcon[i / Nk - 1]) >>> 0;
      } else if (Nk > 6 && i % Nk === 4) {
        tmp = ((sbox[(tmp >>> 24) & 0xff] << 24) | (sbox[(tmp >>> 16) & 0xff] << 16) |
               (sbox[(tmp >>> 8) & 0xff] << 8) | sbox[tmp & 0xff]) >>> 0;
      }
      w[i] = (w[i - Nk] ^ tmp) >>> 0;
    }
    this.ek = w;

    // Inverse key schedule for the equivalent decryption cipher (FIPS-197
    // §5.3.5): reverse the round order, then apply InvMixColumns to the middle
    // round keys (all but the first and last).
    var dw = new Uint32Array(w.length);
    for (i = 0; i <= Nr; i++) {
      for (var jj = 0; jj < 4; jj++) dw[4 * i + jj] = w[4 * (Nr - i) + jj];
    }
    for (i = 4; i < 4 * Nr; i++) {
      var x = dw[i];
      dw[i] = (Td0[sbox[(x >>> 24) & 0xff]] ^ Td1[sbox[(x >>> 16) & 0xff]] ^
               Td2[sbox[(x >>> 8) & 0xff]] ^ Td3[sbox[x & 0xff]]) >>> 0;
    }
    this.dk = dw;
  }

  // Encrypt one 16-byte block: out[oo..] = E(in[io..]).
  AES.prototype.encryptBlock = function (inp, io, out, oo) {
    var ek = this.ek, Nr = this.rounds;
    var s0 = b2w(inp, io) ^ ek[0];
    var s1 = b2w(inp, io + 4) ^ ek[1];
    var s2 = b2w(inp, io + 8) ^ ek[2];
    var s3 = b2w(inp, io + 12) ^ ek[3];
    var t0, t1, t2, t3, k = 4;
    for (var r = 1; r < Nr; r++) {
      t0 = (Te0[(s0 >>> 24) & 0xff] ^ Te1[(s1 >>> 16) & 0xff] ^ Te2[(s2 >>> 8) & 0xff] ^ Te3[s3 & 0xff] ^ ek[k++]) >>> 0;
      t1 = (Te0[(s1 >>> 24) & 0xff] ^ Te1[(s2 >>> 16) & 0xff] ^ Te2[(s3 >>> 8) & 0xff] ^ Te3[s0 & 0xff] ^ ek[k++]) >>> 0;
      t2 = (Te0[(s2 >>> 24) & 0xff] ^ Te1[(s3 >>> 16) & 0xff] ^ Te2[(s0 >>> 8) & 0xff] ^ Te3[s1 & 0xff] ^ ek[k++]) >>> 0;
      t3 = (Te0[(s3 >>> 24) & 0xff] ^ Te1[(s0 >>> 16) & 0xff] ^ Te2[(s1 >>> 8) & 0xff] ^ Te3[s2 & 0xff] ^ ek[k++]) >>> 0;
      s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    out[oo]      = (sbox[(s0 >>> 24) & 0xff] ^ (ek[k] >>> 24)) & 0xff;
    out[oo + 1]  = (sbox[(s1 >>> 16) & 0xff] ^ (ek[k] >>> 16)) & 0xff;
    out[oo + 2]  = (sbox[(s2 >>> 8) & 0xff]  ^ (ek[k] >>> 8)) & 0xff;
    out[oo + 3]  = (sbox[s3 & 0xff]          ^ ek[k]) & 0xff; k++;
    out[oo + 4]  = (sbox[(s1 >>> 24) & 0xff] ^ (ek[k] >>> 24)) & 0xff;
    out[oo + 5]  = (sbox[(s2 >>> 16) & 0xff] ^ (ek[k] >>> 16)) & 0xff;
    out[oo + 6]  = (sbox[(s3 >>> 8) & 0xff]  ^ (ek[k] >>> 8)) & 0xff;
    out[oo + 7]  = (sbox[s0 & 0xff]          ^ ek[k]) & 0xff; k++;
    out[oo + 8]  = (sbox[(s2 >>> 24) & 0xff] ^ (ek[k] >>> 24)) & 0xff;
    out[oo + 9]  = (sbox[(s3 >>> 16) & 0xff] ^ (ek[k] >>> 16)) & 0xff;
    out[oo + 10] = (sbox[(s0 >>> 8) & 0xff]  ^ (ek[k] >>> 8)) & 0xff;
    out[oo + 11] = (sbox[s1 & 0xff]          ^ ek[k]) & 0xff; k++;
    out[oo + 12] = (sbox[(s3 >>> 24) & 0xff] ^ (ek[k] >>> 24)) & 0xff;
    out[oo + 13] = (sbox[(s0 >>> 16) & 0xff] ^ (ek[k] >>> 16)) & 0xff;
    out[oo + 14] = (sbox[(s1 >>> 8) & 0xff]  ^ (ek[k] >>> 8)) & 0xff;
    out[oo + 15] = (sbox[s2 & 0xff]          ^ ek[k]) & 0xff;
  };

  // Decrypt one 16-byte block: out[oo..] = D(in[io..]).
  AES.prototype.decryptBlock = function (inp, io, out, oo) {
    var dk = this.dk, Nr = this.rounds;
    var s0 = b2w(inp, io) ^ dk[0];
    var s1 = b2w(inp, io + 4) ^ dk[1];
    var s2 = b2w(inp, io + 8) ^ dk[2];
    var s3 = b2w(inp, io + 12) ^ dk[3];
    var t0, t1, t2, t3, k = 4;
    for (var r = 1; r < Nr; r++) {
      t0 = (Td0[(s0 >>> 24) & 0xff] ^ Td1[(s3 >>> 16) & 0xff] ^ Td2[(s2 >>> 8) & 0xff] ^ Td3[s1 & 0xff] ^ dk[k++]) >>> 0;
      t1 = (Td0[(s1 >>> 24) & 0xff] ^ Td1[(s0 >>> 16) & 0xff] ^ Td2[(s3 >>> 8) & 0xff] ^ Td3[s2 & 0xff] ^ dk[k++]) >>> 0;
      t2 = (Td0[(s2 >>> 24) & 0xff] ^ Td1[(s1 >>> 16) & 0xff] ^ Td2[(s0 >>> 8) & 0xff] ^ Td3[s3 & 0xff] ^ dk[k++]) >>> 0;
      t3 = (Td0[(s3 >>> 24) & 0xff] ^ Td1[(s2 >>> 16) & 0xff] ^ Td2[(s1 >>> 8) & 0xff] ^ Td3[s0 & 0xff] ^ dk[k++]) >>> 0;
      s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    out[oo]      = (inv[(s0 >>> 24) & 0xff] ^ (dk[k] >>> 24)) & 0xff;
    out[oo + 1]  = (inv[(s3 >>> 16) & 0xff] ^ (dk[k] >>> 16)) & 0xff;
    out[oo + 2]  = (inv[(s2 >>> 8) & 0xff]  ^ (dk[k] >>> 8)) & 0xff;
    out[oo + 3]  = (inv[s1 & 0xff]          ^ dk[k]) & 0xff; k++;
    out[oo + 4]  = (inv[(s1 >>> 24) & 0xff] ^ (dk[k] >>> 24)) & 0xff;
    out[oo + 5]  = (inv[(s0 >>> 16) & 0xff] ^ (dk[k] >>> 16)) & 0xff;
    out[oo + 6]  = (inv[(s3 >>> 8) & 0xff]  ^ (dk[k] >>> 8)) & 0xff;
    out[oo + 7]  = (inv[s2 & 0xff]          ^ dk[k]) & 0xff; k++;
    out[oo + 8]  = (inv[(s2 >>> 24) & 0xff] ^ (dk[k] >>> 24)) & 0xff;
    out[oo + 9]  = (inv[(s1 >>> 16) & 0xff] ^ (dk[k] >>> 16)) & 0xff;
    out[oo + 10] = (inv[(s0 >>> 8) & 0xff]  ^ (dk[k] >>> 8)) & 0xff;
    out[oo + 11] = (inv[s3 & 0xff]          ^ dk[k]) & 0xff; k++;
    out[oo + 12] = (inv[(s3 >>> 24) & 0xff] ^ (dk[k] >>> 24)) & 0xff;
    out[oo + 13] = (inv[(s2 >>> 16) & 0xff] ^ (dk[k] >>> 16)) & 0xff;
    out[oo + 14] = (inv[(s1 >>> 8) & 0xff]  ^ (dk[k] >>> 8)) & 0xff;
    out[oo + 15] = (inv[s0 & 0xff]          ^ dk[k]) & 0xff;
  };

  // ---- Modes ----------------------------------------------------------------

  // Raw CBC decrypt, IV defaults to all-zero. Does NOT remove padding.
  function cbcDecrypt(key, data, iv) {
    if (data.length % 16 !== 0) throw new Error('CBC: data not block-aligned');
    var aes = new AES(key);
    var out = new Uint8Array(data.length);
    var prev = iv ? iv.slice(0, 16) : new Uint8Array(16);
    var block = new Uint8Array(16);
    for (var off = 0; off < data.length; off += 16) {
      aes.decryptBlock(data, off, block, 0);
      for (var i = 0; i < 16; i++) out[off + i] = block[i] ^ prev[i];
      prev = data.subarray(off, off + 16);
    }
    return out;
  }

  // Remove PKCS#7 padding; returns null if padding is invalid.
  function unpadPkcs7(data) {
    if (data.length === 0) return null;
    var c = data[data.length - 1];
    if (c < 1 || c > 16 || c > data.length) return null;
    for (var i = 0; i < c; i++) if (data[data.length - 1 - i] !== c) return null;
    return data.subarray(0, data.length - c);
  }

  // AES-CTR with a 16-byte initial counter block; low 32 bits increment
  // (big-endian), matching the counterCrypt used by iOS keychain GCM.
  function ctrCrypt(key, data, counter0) {
    var aes = new AES(key);
    var out = new Uint8Array(data.length);
    var ctr = counter0.slice(0, 16);
    var ks = new Uint8Array(16);
    for (var off = 0; off < data.length; off += 16) {
      aes.encryptBlock(ctr, 0, ks, 0);
      var n = Math.min(16, data.length - off);
      for (var i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
      // increment low 32 bits (big-endian)
      for (var j = 15; j >= 12; j--) { ctr[j] = (ctr[j] + 1) & 0xff; if (ctr[j]) break; }
    }
    return out;
  }

  // iOS keychain GCM uses a blank IV: J0 = 0^128, so the data counter starts
  // at 0^128 incremented once (0...01). The trailing 16-byte auth tag is not
  // verified here; a successful ASN.1 parse of the plaintext is the integrity
  // signal (same recovered bytes as irestore, which does verify).
  function gcmBlankIvOpen(key, ctAndTag) {
    if (ctAndTag.length < 16) throw new Error('GCM: ciphertext too short');
    var ct = ctAndTag.subarray(0, ctAndTag.length - 16);
    var ctr0 = new Uint8Array(16); ctr0[15] = 1;
    return ctrCrypt(key, ct, ctr0);
  }

  // ---- RFC 3394 AES key unwrap ---------------------------------------------
  // Returns null on failure (e.g. wrong KEK / bad password).
  var RFC3394_IV = [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6];
  function keyUnwrap(kek, wrapped) {
    if (kek.length < 16 || wrapped.length % 8 !== 0 || wrapped.length < 16) return null;
    var aes = new AES(kek);
    var n = wrapped.length / 8 - 1;
    var A = wrapped.slice(0, 8);
    var R = wrapped.slice(0); // R[0] unused; R[1..n] in place
    var B = new Uint8Array(16);
    for (var j = 5; j >= 0; j--) {
      for (var i = n; i >= 1; i--) {
        var t = n * j + i;
        // A ^= t (big-endian) into B[0..7]
        for (var k = 0; k < 8; k++) B[k] = A[k];
        var tt = t, p = 7;
        while (tt && p >= 0) { B[p] ^= tt & 0xff; tt = Math.floor(tt / 256); p--; }
        for (var m = 0; m < 8; m++) B[8 + m] = R[i * 8 + m];
        aes.decryptBlock(B, 0, B, 0);
        for (var a = 0; a < 8; a++) A[a] = B[a];
        for (var b = 0; b < 8; b++) R[i * 8 + b] = B[8 + b];
      }
    }
    for (var c = 0; c < 8; c++) if (A[c] !== RFC3394_IV[c]) return null;
    return R.subarray(8);
  }

  window.KC = window.KC || {};
  window.KC.aes = {
    AES: AES,
    cbcDecrypt: cbcDecrypt,
    unpadPkcs7: unpadPkcs7,
    ctrCrypt: ctrCrypt,
    gcmBlankIvOpen: gcmBlankIvOpen,
    keyUnwrap: keyUnwrap,
    sbox: sbox
  };
})();
