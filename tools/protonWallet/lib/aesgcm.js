// Pure-JS AES-256-GCM (encrypt-block + GHASH), no WebCrypto / no network.
// Written for the Proton Wallet tool so the mnemonic layer decrypts the same
// way everywhere, including a browser opening the file directly over file://
// where crypto.subtle may be unavailable.
//
// Matches the Proton wallet scheme: encrypted blob = IV(12) | ciphertext | tag(16),
// AES-256-GCM, no associated data. (See rust wallet_key.rs UnlockedWalletKey.)
(function () {
  'use strict';

  // --- AES core (key schedule + single block encrypt) ---------------------
  var SBOX = (function () {
    var p = 1, q = 1, sbox = new Uint8Array(256);
    do {
      p = p ^ (p << 1) ^ (p & 0x80 ? 0x11b : 0); p &= 0xff;
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      var xformed = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^
        ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
      sbox[p] = (xformed ^ 0x63) & 0xff;
    } while (p !== 1);
    sbox[0] = 0x63;
    return sbox;
  })();

  var RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d];

  function xtime(a) { return ((a << 1) ^ (a & 0x80 ? 0x11b : 0)) & 0xff; }
  function mul(a, b) {
    var r = 0;
    while (b) { if (b & 1) r ^= a; a = xtime(a); b >>= 1; }
    return r & 0xff;
  }

  function expandKey(key) {
    // AES-256: Nk=8, Nr=14 -> 60 words
    var Nk = 8, Nr = 14, w = new Array(4 * (Nr + 1));
    var i;
    for (i = 0; i < Nk; i++) {
      w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    for (i = Nk; i < 4 * (Nr + 1); i++) {
      var t = w[i - 1].slice();
      if (i % Nk === 0) {
        t = [t[1], t[2], t[3], t[0]];                 // RotWord
        t = [SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]]; // SubWord
        t[0] ^= RCON[(i / Nk) - 1];
      } else if (i % Nk === 4) {
        t = [SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]];
      }
      var p = w[i - Nk];
      w[i] = [p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]];
    }
    return { w: w, Nr: Nr };
  }

  function encryptBlock(sched, inBytes, inOff, out) {
    var w = sched.w, Nr = sched.Nr;
    // state is column-major: s[r][c]
    var s = [[], [], [], []];
    for (var c = 0; c < 4; c++)
      for (var r = 0; r < 4; r++)
        s[r][c] = inBytes[inOff + c * 4 + r];
    addRoundKey(s, w, 0);
    for (var round = 1; round < Nr; round++) {
      subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s, w, round);
    }
    subBytes(s); shiftRows(s); addRoundKey(s, w, Nr);
    for (c = 0; c < 4; c++)
      for (r = 0; r < 4; r++)
        out[c * 4 + r] = s[r][c];
  }

  function addRoundKey(s, w, round) {
    for (var c = 0; c < 4; c++) {
      var k = w[round * 4 + c];
      s[0][c] ^= k[0]; s[1][c] ^= k[1]; s[2][c] ^= k[2]; s[3][c] ^= k[3];
    }
  }
  function subBytes(s) {
    for (var r = 0; r < 4; r++)
      for (var c = 0; c < 4; c++) s[r][c] = SBOX[s[r][c]];
  }
  function shiftRows(s) {
    var t;
    t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
    t = s[2][0]; var u = s[2][1]; s[2][0] = s[2][2]; s[2][1] = s[2][3]; s[2][2] = t; s[2][3] = u;
    t = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = s[3][0]; s[3][0] = t;
  }
  function mixColumns(s) {
    for (var c = 0; c < 4; c++) {
      var a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
      s[0][c] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
      s[1][c] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
      s[2][c] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
      s[3][c] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
    }
  }

  // --- GHASH (GF(2^128) multiply, big-endian bit order) -------------------
  function ghashMul(X, Y) {
    // X, Y: Uint8Array(16); returns Uint8Array(16) = X*Y in GF(2^128)
    var Z = new Uint8Array(16);
    var V = Y.slice();
    for (var i = 0; i < 128; i++) {
      var bit = (X[i >> 3] >> (7 - (i & 7))) & 1;
      if (bit) for (var j = 0; j < 16; j++) Z[j] ^= V[j];
      // V = V >> 1, with reduction if lsb set
      var lsb = V[15] & 1;
      for (var k = 15; k > 0; k--) V[k] = ((V[k] >> 1) | ((V[k - 1] & 1) << 7)) & 0xff;
      V[0] = V[0] >> 1;
      if (lsb) V[0] ^= 0xe1;
    }
    return Z;
  }

  function ghash(H, data) {
    var Y = new Uint8Array(16);
    for (var i = 0; i < data.length; i += 16) {
      for (var j = 0; j < 16; j++) Y[j] ^= (data[i + j] || 0);
      Y = ghashMul(Y, H);
    }
    return Y;
  }

  function incr32(ctr) {
    for (var i = 15; i >= 12; i--) { ctr[i] = (ctr[i] + 1) & 0xff; if (ctr[i]) break; }
  }

  function ctEqual(a, b) {
    if (a.length !== b.length) return false;
    var d = 0;
    for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // Decrypt AES-256-GCM with a 12-byte IV, verifying the 16-byte tag.
  // key: 32 bytes, iv: 12 bytes, ct: ciphertext, tag: 16 bytes.
  // Throws on key/iv size errors; returns {plaintext, authentic:bool}.
  function gcmDecrypt(key, iv, ct, tag) {
    if (key.length !== 32) throw new Error('AES-GCM: key must be 32 bytes');
    if (iv.length !== 12) throw new Error('AES-GCM: IV must be 12 bytes');
    var sched = expandKey(key);

    // H = E_K(0^128)
    var zero = new Uint8Array(16);
    var H = new Uint8Array(16); encryptBlock(sched, zero, 0, H);

    // J0 = IV || 0x00000001 (for 96-bit IV)
    var J0 = new Uint8Array(16);
    J0.set(iv, 0); J0[15] = 1;

    // CTR decrypt starting at inc32(J0)
    var plaintext = new Uint8Array(ct.length);
    var ctr = J0.slice();
    var ks = new Uint8Array(16);
    for (var off = 0; off < ct.length; off += 16) {
      incr32(ctr);
      encryptBlock(sched, ctr, 0, ks);
      var n = Math.min(16, ct.length - off);
      for (var i = 0; i < n; i++) plaintext[off + i] = ct[off + i] ^ ks[i];
    }

    // GHASH over ciphertext (no AAD) then lengths block
    var padLen = (16 - (ct.length % 16)) % 16;
    var ghInput = new Uint8Array(ct.length + padLen + 16);
    ghInput.set(ct, 0);
    // last 16 bytes = [len(AAD)=0 : 8 bytes][len(C) in bits : 8 bytes]
    var ctBits = ct.length * 8;
    var lenBlockOff = ct.length + padLen;
    // AAD length 0 -> bytes already zero
    // write ctBits as 64-bit big-endian into bytes 8..15 of the length block
    var hi = Math.floor(ctBits / 0x100000000);
    var lo = ctBits >>> 0;
    ghInput[lenBlockOff + 8] = (hi >>> 24) & 0xff;
    ghInput[lenBlockOff + 9] = (hi >>> 16) & 0xff;
    ghInput[lenBlockOff + 10] = (hi >>> 8) & 0xff;
    ghInput[lenBlockOff + 11] = hi & 0xff;
    ghInput[lenBlockOff + 12] = (lo >>> 24) & 0xff;
    ghInput[lenBlockOff + 13] = (lo >>> 16) & 0xff;
    ghInput[lenBlockOff + 14] = (lo >>> 8) & 0xff;
    ghInput[lenBlockOff + 15] = lo & 0xff;

    var S = ghash(H, ghInput);

    // T = S XOR E_K(J0)
    var eJ0 = new Uint8Array(16); encryptBlock(sched, J0, 0, eJ0);
    var T = new Uint8Array(16);
    for (var t = 0; t < 16; t++) T[t] = S[t] ^ eJ0[t];

    return { plaintext: plaintext, authentic: ctEqual(T, tag) };
  }

  // Convenience: open a Proton blob laid out as IV(12) | ciphertext | tag(16).
  function gcmOpen(key, blob) {
    if (blob.length < 12 + 16) throw new Error('AES-GCM: blob too short');
    var iv = blob.subarray(0, 12);
    var tag = blob.subarray(blob.length - 16);
    var ct = blob.subarray(12, blob.length - 16);
    return gcmDecrypt(key, iv, ct, tag);
  }

  var api = { gcmDecrypt: gcmDecrypt, gcmOpen: gcmOpen };
  if (typeof window !== 'undefined') { window.ProtonAESGCM = api; }
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
})();
