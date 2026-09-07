/* =========================================================================
   Monero .keys — dekryptering & plånboksåterställning (helt lokalt)
   -------------------------------------------------------------------------
   Portat från Monero-referensen (wallet2 / cryptonote_basic):
     • Ytterbehållaren  keys_file_data : [8-byte chacha-IV][varint längd][ct]
       (::serialization / binary_archive, LEB128-varint)
     • Nyckelhärledning  generate_chacha_key = cn_slow_hash(lösenord)[0..32]
       (CryptoNight variant 0 — se vendor/cryptonight/, cn_slow_hash-global)
     • Dekryptering      ChaCha20 (fallback ChaCha8) av account_data → JSON
     • key_data          epee portable-storage-blob (parseEpee nedan)
     • encrypted_secret_keys=1: hemliga nycklar är XOR:ade med en ChaCha20-
       ström vars nyckel = cn_slow_hash(chacha_key || 0x6b) och IV = m_encryption_iv
     • Adress            base58-blockkodning + keccak256-checksumma
     • Fras (seed)       25-ords Monero-mnemonic (ordlista + CRC32-checksumma)

   keccak256, base58, mnemonic, sc_reduce32, chacha och epee-parsern nedan är
   verifierade byte-för-byte mot en riktig Monero-plånbok (monero-wallet-cli
   v0.18) samt mot python-biblioteket "monero" och OpenSSL:s ChaCha20.
   ========================================================================= */
(function (root) {
    "use strict";

    /* ---------- keccak256 (original Keccak, padding 0x01 — som Monero) ---------- */
    var M64 = (1n << 64n) - 1n;
    var KECCAK_RC = (function () {
        function rcBit(t) { var R = 1; for (var i = 0; i < t % 255; i++) { R <<= 1; if (R & 0x100) R ^= 0x171; } return R & 1; }
        var out = [];
        for (var ir = 0; ir < 24; ir++) { var lane = 0n; for (var j = 0; j <= 6; j++) if (rcBit(j + 7 * ir)) lane |= 1n << BigInt((1 << j) - 1); out.push(lane); }
        return out;
    })();
    var KECCAK_RHO = (function () {
        var o = new Array(25).fill(0), x = 1, y = 0;
        for (var t = 0; t < 24; t++) { o[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64; var nx = y, ny = (2 * x + 3 * y) % 5; x = nx; y = ny; }
        return o;
    })();
    function kRotl(v, n) { n = BigInt(n); return ((v << n) | (v >> (64n - n))) & M64; }
    function kPermute(A) {
        for (var r = 0; r < 24; r++) {
            var C = [];
            for (var x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
            for (var x2 = 0; x2 < 5; x2++) { var D = C[(x2 + 4) % 5] ^ kRotl(C[(x2 + 1) % 5], 1); for (var y = 0; y < 5; y++) A[x2 + 5 * y] ^= D; }
            var B = new Array(25).fill(0n);
            for (var x3 = 0; x3 < 5; x3++) for (var y3 = 0; y3 < 5; y3++) B[y3 + 5 * ((2 * x3 + 3 * y3) % 5)] = kRotl(A[x3 + 5 * y3], KECCAK_RHO[x3 + 5 * y3]);
            for (var x4 = 0; x4 < 5; x4++) for (var y4 = 0; y4 < 5; y4++) A[x4 + 5 * y4] = B[x4 + 5 * y4] ^ ((~B[((x4 + 1) % 5) + 5 * y4] & M64) & B[((x4 + 2) % 5) + 5 * y4]);
            A[0] ^= KECCAK_RC[r];
        }
    }
    function keccak256(bytes) {
        var rate = 136, A = new Array(25).fill(0n);
        var padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
        padded.set(bytes); padded[bytes.length] |= 0x01; padded[padded.length - 1] |= 0x80;
        for (var off = 0; off < padded.length; off += rate) {
            for (var lane = 0; lane < rate / 8; lane++) { var v = 0n; for (var b = 7; b >= 0; b--) v = (v << 8n) | BigInt(padded[off + lane * 8 + b]); A[lane] ^= v; }
            kPermute(A);
        }
        var out = new Uint8Array(32);
        for (var lane2 = 0; lane2 < 4; lane2++) { var v2 = A[lane2]; for (var b2 = 0; b2 < 8; b2++) { out[lane2 * 8 + b2] = Number(v2 & 0xffn); v2 >>= 8n; } }
        return out;
    }

    /* ---------- CRC32 (IEEE, för mnemonic-checksumman) ---------- */
    var CRCT = (function () { var t = new Uint32Array(256); for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
    function crc32(str) { var c = 0xFFFFFFFF; for (var i = 0; i < str.length; i++) c = CRCT[(c ^ str.charCodeAt(i)) & 0xff] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }

    /* ---------- Monero 25-ords mnemonic (english, prefixlängd 3) ---------- */
    function bytesToMnemonic(bytes, words, prefixLen) {
        var n = words.length, out = [];
        for (var i = 0; i < bytes.length; i += 4) {
            var x = ((bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)) >>> 0);
            var w1 = x % n, w2 = (Math.floor(x / n) + w1) % n, w3 = (Math.floor(x / n / n) + w2) % n;
            out.push(words[w1], words[w2], words[w3]);
        }
        var pref = out.map(function (w) { return w.slice(0, prefixLen); }).join('');
        out.push(out[crc32(pref) % out.length]);
        return out.join(' ');
    }

    /* ---------- Monero base58 (blockkodning) ---------- */
    var ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var ENC_SIZE = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    function encBlock(d, o, l) {
        var num = 0n; for (var i = 0; i < l; i++) num = (num << 8n) | BigInt(d[o + i]);
        var size = ENC_SIZE[l], res = new Array(size).fill(ALPHA[0]), j = size - 1;
        while (num > 0n) { res[j--] = ALPHA[Number(num % 58n)]; num /= 58n; }
        return res.join('');
    }
    function b58encode(d) {
        var s = '', full = Math.floor(d.length / 8);
        for (var i = 0; i < full; i++) s += encBlock(d, i * 8, 8);
        var rem = d.length % 8; if (rem) s += encBlock(d, full * 8, rem);
        return s;
    }
    function makeAddress(net, spendPub, viewPub) {
        var p = new Uint8Array(1 + 32 + 32); p[0] = net; p.set(spendPub, 1); p.set(viewPub, 33);
        var cs = keccak256(p).slice(0, 4);
        var f = new Uint8Array(p.length + 4); f.set(p); f.set(cs, p.length);
        return b58encode(f);
    }

    /* ---------- ed25519-scalar reduce (för determinism/visningsnyckel-kontroll) ---------- */
    var L = (1n << 252n) + 27742317777372353535851937790883648493n;
    function scReduce32(bytes) {
        var num = 0n; for (var i = 31; i >= 0; i--) num = (num << 8n) | BigInt(bytes[i]); num %= L;
        var o = new Uint8Array(32); for (var j = 0; j < 32; j++) { o[j] = Number(num & 0xffn); num >>= 8n; }
        return o;
    }

    /* ---------- ChaCha (Monero-layout: 64-bit räknare + 64-bit IV) ---------- */
    function rotl32(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }
    function u32le(p, o) { return (p[o] | (p[o + 1] << 8) | (p[o + 2] << 16) | (p[o + 3] << 24)) >>> 0; }
    function chacha(rounds, data, key, iv) {
        var j = new Uint32Array(16);
        j[0] = 0x61707865; j[1] = 0x3320646e; j[2] = 0x79622d32; j[3] = 0x6b206574;
        for (var i = 0; i < 8; i++) j[4 + i] = u32le(key, i * 4);
        j[12] = 0; j[13] = 0; j[14] = u32le(iv, 0); j[15] = u32le(iv, 4);
        var out = new Uint8Array(data.length), x = new Uint32Array(16), off = 0, len = data.length;
        function QR(a, b, c, d) {
            x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 16);
            x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 12);
            x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 8);
            x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 7);
        }
        while (len > 0) {
            for (var i2 = 0; i2 < 16; i2++) x[i2] = j[i2];
            for (var r = rounds; r > 0; r -= 2) {
                QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
                QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
            }
            var block = new Uint8Array(64);
            for (var i3 = 0; i3 < 16; i3++) { var v = (x[i3] + j[i3]) >>> 0; block[i3 * 4] = v & 0xff; block[i3 * 4 + 1] = (v >>> 8) & 0xff; block[i3 * 4 + 2] = (v >>> 16) & 0xff; block[i3 * 4 + 3] = (v >>> 24) & 0xff; }
            j[12] = (j[12] + 1) >>> 0; if (j[12] === 0) j[13] = (j[13] + 1) >>> 0;
            var nn = Math.min(64, len);
            for (var i4 = 0; i4 < nn; i4++) out[off + i4] = data[off + i4] ^ block[i4];
            off += 64; len -= 64;
        }
        return out;
    }
    function chacha8(d, k, iv) { return chacha(8, d, k, iv); }
    function chacha20(d, k, iv) { return chacha(20, d, k, iv); }

    /* ---------- epee portable storage-parser (för key_data-blobben) ---------- */
    function epeeVarint(b, p) {
        var m = b[p] & 3, v, s;
        if (m === 0) { v = b[p] >>> 2; s = 1; }
        else if (m === 1) { v = ((b[p] | (b[p + 1] << 8)) >>> 0) >>> 2; s = 2; }
        else if (m === 2) { v = ((b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0) >>> 2; s = 4; }
        else { var x = 0n; for (var i = 7; i >= 0; i--) x = (x << 8n) | BigInt(b[p + i]); v = Number(x >> 2n); s = 8; }
        return [v, p + s];
    }
    function readLE(b, p, n) { var x = 0n; for (var i = n - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[p + i]); return x; }
    function epeeValue(b, p, type) {
        if (type & 0x80) {
            var et = type & 0x7f, c; var r = epeeVarint(b, p); c = r[0]; p = r[1];
            var arr = []; for (var i = 0; i < c; i++) { var rr = epeeValue(b, p, et); arr.push(rr[0]); p = rr[1]; }
            return [arr, p];
        }
        switch (type) {
            case 0x0c: return epeeSection(b, p);
            case 0x0a: { var rl = epeeVarint(b, p); var len = rl[0]; p = rl[1]; return [b.slice(p, p + len), p + len]; }
            case 0x01: return [readLE(b, p, 8), p + 8];
            case 0x02: return [Number(readLE(b, p, 4)), p + 4];
            case 0x03: return [Number(readLE(b, p, 2)), p + 2];
            case 0x04: return [b[p], p + 1];
            case 0x05: return [readLE(b, p, 8), p + 8];
            case 0x06: return [Number(readLE(b, p, 4)), p + 4];
            case 0x07: return [Number(readLE(b, p, 2)), p + 2];
            case 0x08: return [b[p], p + 1];
            case 0x09: return [readLE(b, p, 8), p + 8];
            case 0x0b: return [b[p], p + 1];
            default: throw new Error('epee: okänd typ 0x' + type.toString(16));
        }
    }
    function epeeSection(b, p) {
        var rc = epeeVarint(b, p), cnt = rc[0]; p = rc[1];
        var o = {};
        for (var i = 0; i < cnt; i++) {
            var nl = b[p++]; var name = ''; for (var k = 0; k < nl; k++) name += String.fromCharCode(b[p + k]); p += nl;
            var type = b[p++]; var rv = epeeValue(b, p, type); o[name] = rv[0]; p = rv[1];
        }
        return [o, p];
    }
    function parseEpee(b) {
        if (!(b[0] === 0x01 && b[1] === 0x11 && b[2] === 0x01 && b[3] === 0x01 && b[4] === 0x01 && b[5] === 0x01 && b[6] === 0x02 && b[7] === 0x01 && b[8] === 0x01))
            throw new Error('key_data har ogiltig epee-signatur.');
        return epeeSection(b, 9)[0];
    }

    /* ---------- hjälp ---------- */
    function bytesToHex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
    function latin1(bytes) { var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return s; }
    function strToBytes(s) { var a = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i) & 0xff; return a; }
    function eqB(a, b) { if (a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
    function readLEB128(buf, off) { var sh = 0n, res = 0n, i = off; for (; ;) { var b = buf[i++]; res |= BigInt(b & 0x7f) << sh; if (!(b & 0x80)) break; sh += 7n; } return { value: Number(res), next: i }; }

    // nettype (0=main,1=test,2=stage) -> standardadressens nätbyte
    var NET_BYTE = { 0: 18, 1: 53, 2: 24 };
    var NET_NAME = { 18: 'Mainnet', 53: 'Testnet', 24: 'Stagenet' };

    /* ---------- steg 1: härled ChaCha-nyckel ur lösenordet ----------
       cnHash: function(Uint8Array) -> Uint8Array(32)  (CryptoNight variant 0) */
    function deriveChachaKey(passwordBytes, kdfRounds, cnHash) {
        var h = cnHash(passwordBytes);            // 32 byte
        for (var n = 1; n < kdfRounds; n++) h = cnHash(h);
        return h;                                 // hela hashen = chacha_key (32 byte)
    }

    /* ---------- lättviktig strukturkontroll (utan lösenord) ----------
       Verifierar att filen ser ut som en Monero .keys-behållare:
       [8-byte IV][LEB128-varint längd][ciphertext] där längden matchar. */
    function inspectContainer(fileBytes) {
        if (!fileBytes || fileBytes.length < 12) throw new Error('för liten för en .keys-fil');
        var hdr = readLEB128(fileBytes, 8);
        var remaining = fileBytes.length - hdr.next;
        if (hdr.value !== remaining) throw new Error('behållarlängden stämmer inte');
        return { ivHex: bytesToHex(fileBytes.slice(0, 8)), ciphertextLength: hdr.value };
    }

    /* ---------- steg 2: dekryptera ytterlagret → JSON ---------- */
    function decryptOuter(fileBytes, key) {
        if (fileBytes.length < 12) throw new Error('Filen är för liten för att vara en .keys-fil.');
        var iv = fileBytes.slice(0, 8);
        var hdr = readLEB128(fileBytes, 8);
        var ct = fileBytes.slice(hdr.next, hdr.next + hdr.value);
        if (ct.length !== hdr.value) throw new Error('Trasig .keys-fil (längden i behållaren stämmer inte).');
        var obj = null, cipher = null;
        var attempts = [['ChaCha20', chacha20], ['ChaCha8', chacha8]];
        for (var i = 0; i < attempts.length; i++) {
            var pt = attempts[i][1](ct, key, iv);
            try { obj = JSON.parse(latin1(pt)); cipher = attempts[i][0]; break; } catch (e) { obj = null; }
        }
        if (!obj) throw new Error('Kunde inte dekryptera. Fel lösenord, eller en filtyp som inte stöds.');
        return { obj: obj, cipher: cipher, iv: iv };
    }

    /* ---------- steg 3: plocka ut nycklar, ev. avmaska, härled adress/fras ---------- */
    function extractKeys(obj, key, cnHash, netOverride, words) {
        if (typeof obj.key_data !== 'string') throw new Error('key_data saknas i den dekrypterade datan.');
        var root = parseEpee(strToBytes(obj.key_data));
        var mk = root.m_keys;
        if (!mk) throw new Error('m_keys saknas i key_data.');
        var addr = mk.m_account_address || {};
        var spendPub = addr.m_spend_public_key, viewPub = addr.m_view_public_key;
        if (!spendPub || !viewPub) throw new Error('Publika nycklar saknas i key_data.');
        var spendSec = mk.m_spend_secret_key ? mk.m_spend_secret_key.slice() : new Uint8Array(32);
        var viewSec = mk.m_view_secret_key ? mk.m_view_secret_key.slice() : new Uint8Array(32);
        var encIv = mk.m_encryption_iv;
        var encrypted = Number(obj.encrypted_secret_keys || 0) === 1;

        if (encrypted) {
            var ivb = (encIv && encIv.length === 8) ? encIv : new Uint8Array(8);
            var dd = new Uint8Array(33); dd.set(key, 0); dd[32] = 0x6b; // config::HASH_KEY_MEMORY = 'k'
            var derived = cnHash(dd);
            var ks = chacha20(new Uint8Array(64), derived, ivb);
            for (var i = 0; i < 32; i++) { spendSec[i] ^= ks[i]; viewSec[i] ^= ks[32 + i]; }
        }

        var nettype = Number(obj.nettype || 0);
        var net = (netOverride != null) ? netOverride : (NET_BYTE[nettype] != null ? NET_BYTE[nettype] : 18);
        var watchOnly = Number(obj.watch_only || 0) === 1;
        var spendZero = spendSec.every(function (x) { return x === 0; });
        var deterministic = !spendZero && eqB(scReduce32(keccak256(spendSec)), viewSec);

        return {
            cipher: null, // fylls av anroparen
            network: NET_NAME[net] || ('nätbyte ' + net),
            networkByte: net,
            nettypeField: nettype,
            watchOnly: watchOnly,
            encryptedSecretKeys: encrypted,
            deterministic: deterministic,
            seedLanguage: obj.seed_language || null,
            creationTimestamp: (root.m_creation_timestamp != null) ? Number(root.m_creation_timestamp) : null,
            address: makeAddress(net, spendPub, viewPub),
            spendPublicKey: bytesToHex(spendPub),
            viewPublicKey: bytesToHex(viewPub),
            spendSecretKey: spendZero ? null : bytesToHex(spendSec),
            viewSecretKey: bytesToHex(viewSec),
            mnemonic: (watchOnly || spendZero) ? null : bytesToMnemonic(spendSec, words, 3)
        };
    }

    root.MoneroKeys = {
        keccak256: keccak256,
        makeAddress: makeAddress,
        bytesToMnemonic: bytesToMnemonic,
        scReduce32: scReduce32,
        chacha8: chacha8, chacha20: chacha20,
        parseEpee: parseEpee,
        bytesToHex: bytesToHex,
        deriveChachaKey: deriveChachaKey,
        inspectContainer: inspectContainer,
        decryptOuter: decryptOuter,
        extractKeys: extractKeys,
        NET_BYTE: NET_BYTE, NET_NAME: NET_NAME
    };
})(typeof window !== 'undefined' ? window : this);
