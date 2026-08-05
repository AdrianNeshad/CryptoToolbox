// crypto-helpers.js
// Fristående, beroendefria decode-/checksumfunktioner för Magic Tool.
// Ingen extern bibliotek krävs: SHA-256 kommer från Web Crypto (crypto.subtle),
// base58/base58check och bech32/bech32m är rena JS-implementationer.

(function (global) {
    "use strict";

    // ---------- Base58 ----------

    var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Ripple/XRP använder samma teckenuppsättning men i annan ordning.
    var RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

    function base58Decode(str, alphabet) {
        alphabet = alphabet || BASE58_ALPHABET;
        if (!str || typeof str !== "string") return null;

        var map = {};
        for (var i = 0; i < alphabet.length; i++) map[alphabet[i]] = i;

        var num = 0n;
        for (var j = 0; j < str.length; j++) {
            var idx = map[str[j]];
            if (idx === undefined) return null;
            num = num * 58n + BigInt(idx);
        }

        var bytes = [];
        while (num > 0n) {
            bytes.unshift(Number(num & 0xffn));
            num >>= 8n;
        }

        var leadingZeros = 0;
        for (var k = 0; k < str.length; k++) {
            if (str[k] === alphabet[0]) leadingZeros++;
            else break;
        }

        var out = new Uint8Array(leadingZeros + bytes.length);
        out.set(bytes, leadingZeros);
        return out;
    }

    async function sha256(bytes) {
        var digest = await crypto.subtle.digest("SHA-256", bytes);
        return new Uint8Array(digest);
    }

    // Avkodar + verifierar dubbel-SHA256-checksumman (sista 4 byte).
    // Returnerar {full, payload, checksum} vid giltig checksum, annars null.
    async function base58CheckDecode(str, alphabet) {
        var full = base58Decode(str, alphabet);
        if (!full || full.length < 5) return null;

        var payload = full.slice(0, full.length - 4);
        var checksum = full.slice(full.length - 4);

        var hash1 = await sha256(payload);
        var hash2 = await sha256(hash1);

        for (var i = 0; i < 4; i++) {
            if (hash2[i] !== checksum[i]) return null;
        }

        return { full: full, payload: payload, checksum: checksum };
    }

    // ---------- Bech32 / Bech32m (BIP-173 / BIP-350) ----------

    var CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    var BECH32_CONST = 1;
    var BECH32M_CONST = 0x2bc830a3;

    function polymod(values) {
        var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        var chk = 1;
        for (var i = 0; i < values.length; i++) {
            var top = chk >>> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ values[i];
            for (var b = 0; b < 5; b++) {
                if ((top >>> b) & 1) chk ^= GEN[b];
            }
        }
        return chk >>> 0;
    }

    function hrpExpand(hrp) {
        var ret = [];
        for (var i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
        ret.push(0);
        for (var j = 0; j < hrp.length; j++) ret.push(hrp.charCodeAt(j) & 31);
        return ret;
    }

    function verifyChecksum(hrp, data, constant) {
        return polymod(hrpExpand(hrp).concat(data)) === constant;
    }

    function convertBits(data, fromBits, toBits, pad) {
        var acc = 0, bits = 0;
        var ret = [];
        var maxv = (1 << toBits) - 1;
        for (var i = 0; i < data.length; i++) {
            var value = data[i];
            if (value < 0 || (value >> fromBits) !== 0) return null;
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.push((acc >> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
            return null;
        }
        return ret;
    }

    // Avkodar mot ETT specifikt konstant-värde (bech32 ELLER bech32m).
    // Returnerar {hrp, words} (5-bitars ord, checksum borttagen) eller null.
    function bech32DecodeGeneric(bstr, constant) {
        if (!bstr || bstr.length < 8 || bstr.length > 90) return null;
        var lower = bstr.toLowerCase();
        var upper = bstr.toUpperCase();
        if (bstr !== lower && bstr !== upper) return null; // blandad case = ogiltigt
        bstr = lower;

        var pos = bstr.lastIndexOf("1");
        if (pos < 1 || pos + 7 > bstr.length) return null;

        var hrp = bstr.substring(0, pos);
        var dataChars = bstr.substring(pos + 1);
        var data = [];
        for (var i = 0; i < dataChars.length; i++) {
            var d = CHARSET.indexOf(dataChars[i]);
            if (d === -1) return null;
            data.push(d);
        }

        if (!verifyChecksum(hrp, data, constant)) return null;
        return { hrp: hrp, words: data.slice(0, data.length - 6) };
    }

    function bech32Decode(str) {
        return bech32DecodeGeneric(str, BECH32_CONST);
    }

    function bech32mDecode(str) {
        return bech32DecodeGeneric(str, BECH32M_CONST);
    }

    // Högnivåfunktion: försöker både bech32 och bech32m, tolkar segwit-adresser
    // (witness version + program) när hrp ser ut som ett Bitcoin-liknande nät,
    // annars returneras bara den råa bytepayloaden (t.ex. Cosmos-familjens adresser).
    var SEGWIT_HRPS = { bc: true, tb: true, bcrt: true, ltc: true, tltc: true };

    function decodeBech32Address(str) {
        var result = bech32Decode(str);
        var encoding = "bech32";
        if (!result) {
            result = bech32mDecode(str);
            encoding = "bech32m";
        }
        if (!result) return null;

        if (SEGWIT_HRPS[result.hrp] && result.words.length > 0) {
            var witnessVersion = result.words[0];
            var program = convertBits(result.words.slice(1), 5, 8, false);
            if (program) {
                return {
                    hrp: result.hrp,
                    encoding: encoding,
                    witnessVersion: witnessVersion,
                    program: new Uint8Array(program)
                };
            }
        }

        var raw = convertBits(result.words, 5, 8, false);
        return {
            hrp: result.hrp,
            encoding: encoding,
            witnessVersion: null,
            program: raw ? new Uint8Array(raw) : new Uint8Array(0)
        };
    }

    global.CryptoHelpers = {
        BASE58_ALPHABET: BASE58_ALPHABET,
        RIPPLE_ALPHABET: RIPPLE_ALPHABET,
        base58Decode: base58Decode,
        base58CheckDecode: base58CheckDecode,
        sha256: sha256,
        bech32Decode: bech32Decode,
        bech32mDecode: bech32mDecode,
        decodeBech32Address: decodeBech32Address,
        convertBits: convertBits
    };
})(window);
