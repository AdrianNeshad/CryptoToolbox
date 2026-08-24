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

    // ---------- Keccak-256 ----------
    // Original Keccak (padding 0x01), samma variant som Ethereum och Monero
    // använder — INTE NIST SHA-3 (padding 0x06). BigInt-baserad implementation:
    // långsammare än optimerade 32-bitarsvarianter men körs bara på korta
    // indata (adresser), så prestandan är irrelevant här. Runda-konstanter och
    // rho-offsets genereras algoritmiskt enligt FIPS 202 istället för att
    // hårdkodas.

    var KECCAK_MASK64 = (1n << 64n) - 1n;

    var KECCAK_RC = (function () {
        function rcBit(t) {
            var R = 1;
            for (var i = 0; i < t % 255; i++) {
                R <<= 1;
                if (R & 0x100) R ^= 0x171;
            }
            return R & 1;
        }
        var out = [];
        for (var ir = 0; ir < 24; ir++) {
            var lane = 0n;
            for (var j = 0; j <= 6; j++) {
                if (rcBit(j + 7 * ir)) lane |= 1n << BigInt((1 << j) - 1);
            }
            out.push(lane);
        }
        return out;
    })();

    var KECCAK_RHO = (function () {
        var offs = [];
        for (var i = 0; i < 25; i++) offs.push(0);
        var x = 1, y = 0;
        for (var t = 0; t < 24; t++) {
            offs[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;
            var nx = y, ny = (2 * x + 3 * y) % 5;
            x = nx; y = ny;
        }
        return offs;
    })();

    function keccakRotl(v, n) {
        n = BigInt(n);
        return ((v << n) | (v >> (64n - n))) & KECCAK_MASK64;
    }

    function keccakPermute(A) {
        for (var round = 0; round < 24; round++) {
            var C = [];
            for (var x = 0; x < 5; x++) {
                C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
            }
            for (var x2 = 0; x2 < 5; x2++) {
                var D = C[(x2 + 4) % 5] ^ keccakRotl(C[(x2 + 1) % 5], 1);
                for (var y = 0; y < 5; y++) A[x2 + 5 * y] ^= D;
            }
            var B = [];
            for (var i = 0; i < 25; i++) B.push(0n);
            for (var x3 = 0; x3 < 5; x3++) {
                for (var y3 = 0; y3 < 5; y3++) {
                    B[y3 + 5 * ((2 * x3 + 3 * y3) % 5)] = keccakRotl(A[x3 + 5 * y3], KECCAK_RHO[x3 + 5 * y3]);
                }
            }
            for (var x4 = 0; x4 < 5; x4++) {
                for (var y4 = 0; y4 < 5; y4++) {
                    A[x4 + 5 * y4] = B[x4 + 5 * y4] ^ ((~B[((x4 + 1) % 5) + 5 * y4] & KECCAK_MASK64) & B[((x4 + 2) % 5) + 5 * y4]);
                }
            }
            A[0] ^= KECCAK_RC[round];
        }
    }

    function keccak256(bytes) {
        var rate = 136;
        var A = [];
        for (var i = 0; i < 25; i++) A.push(0n);

        var padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
        padded.set(bytes);
        padded[bytes.length] |= 0x01;
        padded[padded.length - 1] |= 0x80;

        for (var off = 0; off < padded.length; off += rate) {
            for (var lane = 0; lane < rate / 8; lane++) {
                var v = 0n;
                for (var b = 7; b >= 0; b--) {
                    v = (v << 8n) | BigInt(padded[off + lane * 8 + b]);
                }
                A[lane] ^= v;
            }
            keccakPermute(A);
        }

        var out = new Uint8Array(32);
        for (var lane2 = 0; lane2 < 4; lane2++) {
            var v2 = A[lane2];
            for (var b2 = 0; b2 < 8; b2++) {
                out[lane2 * 8 + b2] = Number(v2 & 0xffn);
                v2 >>= 8n;
            }
        }
        return out;
    }

    function toHexString(u8) {
        var s = "";
        for (var i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
        return s;
    }

    function asciiBytes(str) {
        var out = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
        return out;
    }

    // EIP-55-checksumverifiering av en EVM-adress. hex40 = 40 hextecken utan
    // 0x-prefix, med blandad case. Returnerar true om casingen exakt matchar
    // keccak256-hashen av den gemena adressen.
    function checkEip55(hex40) {
        var lower = hex40.toLowerCase();
        var hash = toHexString(keccak256(asciiBytes(lower)));
        for (var i = 0; i < 40; i++) {
            var c = hex40[i];
            if (c >= "0" && c <= "9") continue;
            var shouldUpper = parseInt(hash[i], 16) >= 8;
            if (shouldUpper !== (c >= "A" && c <= "F")) return false;
        }
        return true;
    }

    // ---------- Monero base58 (blockkodning) ----------
    // Monero kodar 8-byte-block till 11 tecken (sista blocket kortare), till
    // skillnad från Bitcoins bigint-base58. Checksumman är de första 4 byten av
    // keccak256 över resten av payloaden.

    var MONERO_DECODED_BLOCK_SIZES = { 2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8 };

    function moneroBase58Decode(str) {
        var map = {};
        for (var i = 0; i < BASE58_ALPHABET.length; i++) map[BASE58_ALPHABET[i]] = i;

        var fullBlocks = Math.floor(str.length / 11);
        var lastChars = str.length % 11;
        var lastBytes = lastChars === 0 ? 0 : MONERO_DECODED_BLOCK_SIZES[lastChars];
        if (lastChars !== 0 && lastBytes === undefined) return null;

        var out = [];
        function decodeBlock(block, byteLen) {
            var num = 0n;
            for (var i = 0; i < block.length; i++) {
                var d = map[block[i]];
                if (d === undefined) return false;
                num = num * 58n + BigInt(d);
            }
            var bytes = [];
            for (var j = 0; j < byteLen; j++) {
                bytes.unshift(Number(num & 0xffn));
                num >>= 8n;
            }
            if (num > 0n) return false;
            for (var k = 0; k < bytes.length; k++) out.push(bytes[k]);
            return true;
        }

        for (var b = 0; b < fullBlocks; b++) {
            if (!decodeBlock(str.slice(b * 11, b * 11 + 11), 8)) return null;
        }
        if (lastChars) {
            if (!decodeBlock(str.slice(fullBlocks * 11), lastBytes)) return null;
        }
        return new Uint8Array(out);
    }

    // Avkodar + checksumverifierar en Monero-adress.
    // Returnerar {network, payloadLength} vid giltig checksum, annars null.
    function decodeMoneroAddress(str) {
        var raw = moneroBase58Decode(str);
        if (!raw || raw.length < 5) return null;
        var payload = raw.slice(0, raw.length - 4);
        var checksum = raw.slice(raw.length - 4);
        var hash = keccak256(payload);
        for (var i = 0; i < 4; i++) {
            if (hash[i] !== checksum[i]) return null;
        }
        return { network: raw[0], payloadLength: payload.length };
    }

    // ---------- CashAddr (Bitcoin Cash) ----------
    // BCH:s adressformat: samma teckenuppsättning som bech32 men 40-bitars
    // polymod-checksumma som täcker även prefixet ("bitcoincash" etc.).

    var CASHADDR_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    function cashPolymod(values) {
        var GEN = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
        var chk = 1n;
        for (var i = 0; i < values.length; i++) {
            var top = chk >> 35n;
            chk = ((chk & 0x07ffffffffn) << 5n) ^ BigInt(values[i]);
            for (var b = 0; b < 5; b++) {
                if ((top >> BigInt(b)) & 1n) chk ^= GEN[b];
            }
        }
        return chk ^ 1n;
    }

    // Verifierar checksumman och returnerar {versionByte, hash} eller null.
    // prefix anges utan kolon (t.ex. "bitcoincash"), data är payload-delen.
    function decodeCashAddr(prefix, data) {
        data = data.toLowerCase();
        var values = [];
        for (var i = 0; i < prefix.length; i++) values.push(prefix.charCodeAt(i) & 0x1f);
        values.push(0);
        for (var j = 0; j < data.length; j++) {
            var d = CASHADDR_CHARSET.indexOf(data[j]);
            if (d === -1) return null;
            values.push(d);
        }
        if (values.length < prefix.length + 1 + 9) return null;
        if (cashPolymod(values) !== 0n) return null;

        var payload = values.slice(prefix.length + 1, values.length - 8);
        var bytes = convertBits(payload, 5, 8, false);
        if (!bytes || bytes.length < 2) return null;
        return { versionByte: bytes[0], hash: new Uint8Array(bytes.slice(1)) };
    }

    // ---------- TON-adresser (CRC16-XMODEM) ----------

    function crc16Xmodem(bytes) {
        var crc = 0;
        for (var i = 0; i < bytes.length; i++) {
            crc ^= bytes[i] << 8;
            for (var b = 0; b < 8; b++) {
                crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
            }
        }
        return crc;
    }

    // TON user-friendly-adress: 48 tecken base64/base64url = 36 byte
    // (1 taggbyte + 1 workchain + 32 byte hash + 2 byte CRC16).
    // Returnerar {bounceable, testOnly, workchain} vid giltig CRC, annars null.
    function decodeTonAddress(str) {
        if (!/^[A-Za-z0-9+/_-]{48}$/.test(str)) return null;
        var b64 = str.replace(/-/g, "+").replace(/_/g, "/");
        var bin;
        try { bin = atob(b64); } catch (e) { return null; }
        if (bin.length !== 36) return null;
        var raw = new Uint8Array(36);
        for (var i = 0; i < 36; i++) raw[i] = bin.charCodeAt(i);

        var tag = raw[0];
        var base = tag & 0x7f;
        if (base !== 0x11 && base !== 0x51) return null;

        var crc = crc16Xmodem(raw.subarray(0, 34));
        if (raw[34] !== (crc >> 8) || raw[35] !== (crc & 0xff)) return null;

        return {
            bounceable: base === 0x11,
            testOnly: (tag & 0x80) !== 0,
            workchain: raw[1] === 0xff ? -1 : raw[1]
        };
    }

    // ---------- secp256k1 ----------

    var SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    var SECP256K1_P = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

    // En 32-byte-skalär är en giltig secp256k1-privatnyckel om 0 < k < n.
    function isValidSecp256k1Scalar(hex) {
        if (!/^[0-9a-fA-F]{64}$/.test(hex)) return false;
        var v = BigInt("0x" + hex);
        return v > 0n && v < SECP256K1_N;
    }

    function modPow(base, exp, mod) {
        var result = 1n;
        base %= mod;
        while (exp > 0n) {
            if (exp & 1n) result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1n;
        }
        return result;
    }

    // Verifierar att (x, y) ligger på kurvan y² = x³ + 7 (mod p). En slumpmässig
    // 64-byte-sträng klarar detta med sannolikhet ~2^-256, så en träff är ett
    // kryptografiskt starkt bevis på att det är en riktig okomprimerad nyckel.
    function isPointOnSecp256k1(xHex, yHex) {
        if (!/^[0-9a-fA-F]{64}$/.test(xHex) || !/^[0-9a-fA-F]{64}$/.test(yHex)) return false;
        var x = BigInt("0x" + xHex);
        var y = BigInt("0x" + yHex);
        if (x <= 0n || x >= SECP256K1_P || y <= 0n || y >= SECP256K1_P) return false;
        var diff = (y * y - x * x * x - 7n) % SECP256K1_P;
        return ((diff + SECP256K1_P) % SECP256K1_P) === 0n;
    }

    // För komprimerade nycklar finns bara x: kontrollera att x³ + 7 är en
    // kvadratisk rest mod p (dvs. att en y-koordinat existerar). p ≡ 3 (mod 4)
    // så kandidaten är (x³+7)^((p+1)/4). En slumpmässig x klarar detta med
    // ~50 % sannolikhet — det är alltså en svag indikation, ingen verifiering,
    // men ett misslyckande bevisar att strängen INTE är en giltig secp256k1-nyckel.
    function hasValidSecp256k1X(xHex) {
        if (!/^[0-9a-fA-F]{64}$/.test(xHex)) return false;
        var x = BigInt("0x" + xHex);
        if (x <= 0n || x >= SECP256K1_P) return false;
        var y2 = (x * x * x + 7n) % SECP256K1_P;
        var y = modPow(y2, (SECP256K1_P + 1n) / 4n, SECP256K1_P);
        return (y * y) % SECP256K1_P === y2;
    }

    // ---------- HMAC-SHA512 (för Electrum-seedversioner) ----------

    async function hmacSha512(keyStr, msgStr) {
        var enc = new TextEncoder();
        var key = await crypto.subtle.importKey(
            "raw", enc.encode(keyStr),
            { name: "HMAC", hash: "SHA-512" },
            false, ["sign"]
        );
        var sig = await crypto.subtle.sign("HMAC", key, enc.encode(msgStr));
        return new Uint8Array(sig);
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
        convertBits: convertBits,
        keccak256: keccak256,
        checkEip55: checkEip55,
        decodeMoneroAddress: decodeMoneroAddress,
        decodeCashAddr: decodeCashAddr,
        decodeTonAddress: decodeTonAddress,
        isValidSecp256k1Scalar: isValidSecp256k1Scalar,
        isPointOnSecp256k1: isPointOnSecp256k1,
        hasValidSecp256k1X: hasValidSecp256k1X,
        hmacSha512: hmacSha512
    };
})(window);
