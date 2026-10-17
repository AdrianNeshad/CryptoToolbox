// SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes.
// A from-spec JavaScript port of the reference implementation
// (trezor/python-shamir-mnemonic), validated against its vectors.json.
//
// Pure client-side. Hashing (PBKDF2-HMAC-SHA256, HMAC-SHA256) uses the
// browser's built-in WebCrypto; randomness uses crypto.getRandomValues. Works
// unchanged in Node 18+ (globalThis.crypto) for the offline test suite.
//
// Besides split / combine this also exposes:
//   - share inspection (every header field, even when the checksum fails)
//   - flexible recovery (surplus shares, subset search on a bad digest,
//     detection of shares that do not lie on the group polynomial)
//   - share regeneration (any member index of a group from T shares)
//   - re-sharing an extendable backup under a new identifier
//   - RS1024 erasure solving for unreadable / mistyped words

(function (root, factory) {
    "use strict";
    var words = root.SLIP39_WORDLIST ||
        (typeof require === "function" ? require("./wordlist.js") : null);
    var api = factory(root, words);
    if (typeof module === "object" && module.exports) module.exports = api;
    root.SLIP39 = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root, WORDLIST) {
    "use strict";

    if (!WORDLIST || WORDLIST.length !== 1024) {
        throw new Error("SLIP-39 wordlist missing or incomplete.");
    }

    // ---------- Constants (names follow the reference implementation) ----------

    var RADIX_BITS = 10;
    var ID_LENGTH_BITS = 15;
    var ITERATION_EXP_LENGTH_BITS = 4;
    var ID_EXP_LENGTH_WORDS = 2;
    var MAX_SHARE_COUNT = 16;
    var CHECKSUM_LENGTH_WORDS = 3;
    var DIGEST_LENGTH_BYTES = 4;
    var CS_ORIG = "shamir";
    var CS_EXTENDABLE = "shamir_extendable";
    var GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1;
    var METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS; // 7
    var MIN_STRENGTH_BITS = 128;
    var MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + Math.ceil(MIN_STRENGTH_BITS / RADIX_BITS); // 20
    var BASE_ITERATION_COUNT = 10000;
    var ROUND_COUNT = 4;
    var SECRET_INDEX = 255;
    var DIGEST_INDEX = 254;

    var WORD_INDEX = Object.create(null);
    WORDLIST.forEach(function (w, i) { WORD_INDEX[w] = i; });

    // Every word is uniquely identified by its first four letters.
    var PREFIX_INDEX = Object.create(null);
    WORDLIST.forEach(function (w, i) { PREFIX_INDEX[w.slice(0, 4)] = i; });

    function Slip39Error(message, code) {
        var e = new Error(message);
        e.name = "Slip39Error";
        e.code = code || "invalid";
        return e;
    }

    // ---------- Byte helpers ----------

    function bytesToHex(bytes) {
        var s = "";
        for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
        return s;
    }

    function hexToBytes(hex) {
        var h = String(hex).replace(/^0x/i, "").replace(/\s+/g, "");
        if (h.length % 2 !== 0 || /[^0-9a-f]/i.test(h)) throw Slip39Error("Not a valid hex string.", "hex");
        var out = new Uint8Array(h.length / 2);
        for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
        return out;
    }

    function asciiBytes(str) {
        str = str || "";
        var out = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c < 32 || c > 126) {
                throw Slip39Error("The passphrase must contain only printable ASCII characters " +
                    "(code points 32-126). Found \"" + str.charAt(i) + "\" at position " + (i + 1) + ".", "passphrase");
            }
            out[i] = c;
        }
        return out;
    }

    function concatBytes() {
        var len = 0, i;
        for (i = 0; i < arguments.length; i++) len += arguments[i].length;
        var out = new Uint8Array(len), off = 0;
        for (i = 0; i < arguments.length; i++) { out.set(arguments[i], off); off += arguments[i].length; }
        return out;
    }

    function bytesEqual(a, b) {
        if (a.length !== b.length) return false;
        var d = 0;
        for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i];
        return d === 0;
    }

    function xorBytes(a, b) {
        var out = new Uint8Array(a.length);
        for (var i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
        return out;
    }

    function csCodes(extendable) {
        var s = extendable ? CS_EXTENDABLE : CS_ORIG;
        var out = [];
        for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
        return out;
    }

    // ---------- Randomness (overridable for deterministic tests) ----------

    var randomBytes = function (n) {
        var out = new Uint8Array(n);
        if (n > 0) root.crypto.getRandomValues(out);
        return out;
    };

    // ---------- WebCrypto primitives ----------

    function subtle() {
        var c = root.crypto;
        if (!c || !c.subtle) {
            throw Slip39Error("WebCrypto is not available in this window. Open the tool from CryptoToolbox " +
                "(file:// or the desktop app) rather than an insecure http:// page.", "webcrypto");
        }
        return c.subtle;
    }

    function hmacSha256(key, msg) {
        // WebCrypto rejects zero-length HMAC keys; that only happens for a
        // 4-byte secret, which SLIP-39 never allows (>= 16 bytes).
        return subtle().importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
            .then(function (k) { return subtle().sign("HMAC", k, msg); })
            .then(function (sig) { return new Uint8Array(sig); });
    }

    function pbkdf2Sha256(password, salt, iterations, dkLen) {
        return subtle().importKey("raw", password, "PBKDF2", false, ["deriveBits"])
            .then(function (k) {
                return subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iterations }, k, dkLen * 8);
            })
            .then(function (bits) { return new Uint8Array(bits); });
    }

    // ---------- RS1024 checksum ----------

    var GEN = [0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
        0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120];

    function polymod(values) {
        var chk = 1;
        for (var p = 0; p < values.length; p++) {
            var b = chk >>> 20;
            chk = ((chk & 0xFFFFF) << 10) ^ values[p];
            for (var i = 0; i < 10; i++) {
                if ((b >>> i) & 1) chk ^= GEN[i];
            }
        }
        return chk;
    }

    function rs1024CreateChecksum(data, extendable) {
        var pm = polymod(csCodes(extendable).concat(data, [0, 0, 0])) ^ 1;
        return [(pm >>> 20) & 1023, (pm >>> 10) & 1023, pm & 1023];
    }

    function rs1024VerifyChecksum(data, extendable) {
        return polymod(csCodes(extendable).concat(data)) === 1;
    }

    // ---------- Bit packing between bytes and 10-bit words ----------

    // Left-pads with zero bits to a multiple of 10, big-endian.
    function bytesToWordIndices(bytes) {
        var wordCount = Math.ceil(bytes.length * 8 / RADIX_BITS);
        var pad = wordCount * RADIX_BITS - bytes.length * 8;
        var out = [], acc = 0, bits = pad;
        for (var i = 0; i < bytes.length; i++) {
            acc = (acc << 8) | bytes[i];
            bits += 8;
            while (bits >= RADIX_BITS) {
                bits -= RADIX_BITS;
                out.push((acc >>> bits) & 1023);
            }
            acc &= (1 << bits) - 1;
        }
        return out;
    }

    // Returns null when the leading padding bits are not all zero.
    function wordIndicesToBytes(indices, padLen) {
        var totalBits = indices.length * RADIX_BITS;
        var out = new Uint8Array((totalBits - padLen) / 8);
        var acc = 0, bits = 0, skip = padLen, o = 0;
        for (var i = 0; i < indices.length; i++) {
            acc = (acc << RADIX_BITS) | indices[i];
            bits += RADIX_BITS;
            if (skip > 0) {
                var take = Math.min(skip, bits);
                if ((acc >>> (bits - take)) !== 0) return null;
                bits -= take;
                skip -= take;
                acc &= (1 << bits) - 1;
            }
            while (bits >= 8) {
                bits -= 8;
                out[o++] = (acc >>> bits) & 0xff;
            }
            acc &= (1 << bits) - 1;
        }
        return out;
    }

    // ---------- Mnemonic text handling ----------

    // Splits free text into word tokens. Numbering such as "1." or "(12)",
    // commas and other punctuation are ignored; "?", "_" or "*" mark a word
    // that is unknown / unreadable.
    function tokenize(text) {
        var raw = String(text || "").toLowerCase().split(/[\s,;]+/);
        var out = [];
        raw.forEach(function (t) {
            if (!t) return;
            if (/^[?_*]+$/.test(t) || t === "…") { out.push("?"); return; }
            t = t.replace(/^[^a-z?]+|[^a-z?]+$/g, "");
            if (!t) return;
            if (/^\d+[.)]?$/.test(t)) return;
            out.push(t);
        });
        return out;
    }

    function editDistance(a, b) {
        // Damerau-Levenshtein (optimal string alignment)
        var d = [], i, j;
        for (i = 0; i <= a.length; i++) { d[i] = [i]; }
        for (j = 0; j <= b.length; j++) { d[0][j] = j; }
        for (i = 1; i <= a.length; i++) {
            for (j = 1; j <= b.length; j++) {
                var cost = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
                d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
                if (i > 1 && j > 1 && a.charAt(i - 1) === b.charAt(j - 2) && a.charAt(i - 2) === b.charAt(j - 1)) {
                    d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
                }
            }
        }
        return d[a.length][b.length];
    }

    function suggestWords(token, n) {
        n = n || 5;
        return WORDLIST.map(function (w) { return { w: w, d: editDistance(token, w) }; })
            .sort(function (x, y) { return x.d - y.d || (x.w < y.w ? -1 : 1); })
            .slice(0, n)
            .map(function (x) { return x.w; });
    }

    // Resolves tokens to word indices. Each entry:
    //   { token, index, word, status }  status: "ok" | "prefix" | "fuzzy" | "unknown" | "placeholder"
    //   "prefix": an unambiguous abbreviation (e.g. the 4-letter form Trezor accepts)
    //   "fuzzy":  the first four letters match a word but the rest differ
    function resolveWords(text) {
        var tokens = Array.isArray(text) ? text : tokenize(text);
        return tokens.map(function (t) {
            if (t === "?") return { token: t, index: null, word: null, status: "placeholder" };
            if (t in WORD_INDEX) return { token: t, index: WORD_INDEX[t], word: t, status: "ok" };
            if (t.length >= 4 && (t.slice(0, 4) in PREFIX_INDEX)) {
                var idx = PREFIX_INDEX[t.slice(0, 4)];
                var w = WORDLIST[idx];
                return { token: t, index: idx, word: w, status: w.indexOf(t) === 0 ? "prefix" : "fuzzy" };
            }
            if (t.length >= 1 && t.length < 4) {
                var matches = WORDLIST.filter(function (x) { return x.indexOf(t) === 0; });
                if (matches.length === 1) return { token: t, index: WORD_INDEX[matches[0]], word: matches[0], status: "prefix" };
            }
            return { token: t, index: null, word: null, status: "unknown", suggestions: suggestWords(t) };
        });
    }

    // Strict conversion used by decode: every word must resolve.
    function mnemonicToIndices(mnemonic) {
        if (Array.isArray(mnemonic) && typeof mnemonic[0] === "number") return mnemonic.slice();
        var res = resolveWords(mnemonic);
        var bad = res.filter(function (r) { return r.index === null; });
        if (bad.length) {
            throw Slip39Error("Invalid mnemonic word \"" + bad[0].token + "\".", "word");
        }
        return res.map(function (r) { return r.index; });
    }

    function indicesToWords(indices) {
        return indices.map(function (i) { return WORDLIST[i]; });
    }

    // ---------- Share encoding / decoding ----------

    function validLengthWords(n) {
        if (n < MIN_MNEMONIC_LENGTH_WORDS) return false;
        return (RADIX_BITS * (n - METADATA_LENGTH_WORDS)) % 16 <= 8;
    }

    // Decodes every field without throwing, so a damaged share can still be
    // shown. `checks` lists each validity rule; `ok` is true when all pass.
    function inspectIndices(indices) {
        var n = indices.length;
        var res = { indices: indices.slice(), words: indicesToWords(indices), wordCount: n, checks: [], ok: true };
        function check(id, pass, label, detail) {
            res.checks.push({ id: id, pass: pass, label: label, detail: detail || "" });
            if (!pass) res.ok = false;
        }

        if (n < ID_EXP_LENGTH_WORDS + 2) {
            check("length", false, "Length", "Too short to contain a share header (" + n + " words).");
            return res;
        }

        var idExp = (indices[0] << 10) | indices[1];
        res.identifier = idExp >>> 5;
        res.extendable = ((idExp >>> 4) & 1) === 1;
        res.iterationExponent = idExp & 15;
        res.iterations = BASE_ITERATION_COUNT * Math.pow(2, res.iterationExponent);

        var sp = (indices[2] << 10) | indices[3];
        res.groupIndex = (sp >>> 16) & 15;
        res.groupThreshold = ((sp >>> 12) & 15) + 1;
        res.groupCount = ((sp >>> 8) & 15) + 1;
        res.memberIndex = (sp >>> 4) & 15;
        res.memberThreshold = (sp & 15) + 1;
        res.customization = res.extendable ? CS_EXTENDABLE : CS_ORIG;

        var lengthOk = n >= MIN_MNEMONIC_LENGTH_WORDS;
        check("length", lengthOk, "Length",
            lengthOk ? n + " words" : n + " words — a share needs at least " + MIN_MNEMONIC_LENGTH_WORDS + " words.");

        var padLen = (RADIX_BITS * (n - METADATA_LENGTH_WORDS)) % 16;
        res.paddingBits = padLen;
        var padLenOk = padLen <= 8;
        if (lengthOk) {
            check("padlen", padLenOk, "Word count",
                padLenOk ? "A valid share length" : n + " words is not a valid share length " +
                    "(" + (n - 1 >= 20 && validLengthWords(n - 1) ? "one word too many?" : validLengthWords(n + 1) ? "one word missing?" : "check the word count") + ").");
        }

        var checksumOk = rs1024VerifyChecksum(indices, res.extendable);
        res.checksumOk = checksumOk;
        check("checksum", checksumOk, "RS1024 checksum",
            checksumOk ? "Valid (customization \"" + res.customization + "\")" : "Invalid — at least one word is wrong, missing or out of order.");

        check("threshold", res.groupThreshold <= res.groupCount, "Group threshold",
            res.groupThreshold + " of " + res.groupCount + (res.groupThreshold <= res.groupCount ? "" : " — the threshold cannot exceed the group count."));

        if (lengthOk && padLenOk && n > METADATA_LENGTH_WORDS) {
            var valueWords = indices.slice(ID_EXP_LENGTH_WORDS + 2, n - CHECKSUM_LENGTH_WORDS);
            var value = wordIndicesToBytes(valueWords, padLen);
            check("padding", value !== null, "Padding bits",
                value !== null ? padLen + " leading zero bit" + (padLen === 1 ? "" : "s") : "The " + padLen + " padding bits are not zero.");
            if (value) {
                res.value = value;
                res.valueBits = value.length * 8;
                check("strength", value.length * 8 >= MIN_STRENGTH_BITS && value.length % 2 === 0, "Share value",
                    value.length * 8 + " bits" + (value.length * 8 >= MIN_STRENGTH_BITS && value.length % 2 === 0 ? "" : " — must be at least 128 bits and a multiple of 16."));
            }
        }
        return res;
    }

    function shareFromInspection(r, mnemonicPreview) {
        if (!r.ok) {
            var failed = r.checks.filter(function (c) { return !c.pass; })[0];
            var code = failed ? failed.id : "invalid";
            var msg = failed ? failed.label + ": " + failed.detail : "Invalid share.";
            if (failed && failed.id === "checksum") msg = "Invalid mnemonic checksum for \"" + mnemonicPreview + " ...\".";
            if (failed && failed.id === "padding") msg = "Invalid mnemonic padding for \"" + mnemonicPreview + " ...\".";
            if (failed && (failed.id === "length" || failed.id === "padlen")) msg = "Invalid mnemonic length. " + failed.detail;
            throw Slip39Error(msg, code);
        }
        return {
            identifier: r.identifier,
            extendable: r.extendable,
            iterationExponent: r.iterationExponent,
            groupIndex: r.groupIndex,
            groupThreshold: r.groupThreshold,
            groupCount: r.groupCount,
            memberIndex: r.memberIndex,
            memberThreshold: r.memberThreshold,
            value: r.value,
            indices: r.indices,
            words: r.words
        };
    }

    function decodeShare(mnemonic) {
        var indices = mnemonicToIndices(mnemonic);
        var r = inspectIndices(indices);
        return shareFromInspection(r, r.words.slice(0, ID_EXP_LENGTH_WORDS + 2).join(" "));
    }

    function encodeShare(s) {
        var idExp = (s.identifier << 5) | ((s.extendable ? 1 : 0) << 4) | s.iterationExponent;
        var sp = (s.groupIndex << 16) | ((s.groupThreshold - 1) << 12) | ((s.groupCount - 1) << 8) |
            (s.memberIndex << 4) | (s.memberThreshold - 1);
        var data = [(idExp >>> 10) & 1023, idExp & 1023, (sp >>> 10) & 1023, sp & 1023]
            .concat(bytesToWordIndices(s.value));
        var indices = data.concat(rs1024CreateChecksum(data, s.extendable));
        return indicesToWords(indices);
    }

    function makeShare(params, memberIndex, value) {
        var s = {
            identifier: params.identifier,
            extendable: params.extendable,
            iterationExponent: params.iterationExponent,
            groupIndex: params.groupIndex,
            groupThreshold: params.groupThreshold,
            groupCount: params.groupCount,
            memberIndex: memberIndex,
            memberThreshold: params.memberThreshold,
            value: value
        };
        s.words = encodeShare(s);
        s.indices = s.words.map(function (w) { return WORD_INDEX[w]; });
        s.mnemonic = s.words.join(" ");
        return s;
    }

    function commonKey(s) {
        return [s.identifier, s.extendable ? 1 : 0, s.iterationExponent, s.groupThreshold, s.groupCount, s.value.length].join(":");
    }

    // ---------- GF(256) Shamir ----------

    var EXP = new Array(255), LOG = new Array(256);
    (function () {
        var poly = 1;
        for (var i = 0; i < 255; i++) {
            EXP[i] = poly;
            LOG[poly] = i;
            poly = (poly << 1) ^ poly;      // multiply by x + 1
            if (poly & 0x100) poly ^= 0x11B; // reduce by x^8 + x^4 + x^3 + x + 1
        }
    })();

    // shares: [{ x, data: Uint8Array }]
    function interpolate(shares, x) {
        var xs = {}, len = null, i, j;
        for (i = 0; i < shares.length; i++) {
            if (xs[shares[i].x]) throw Slip39Error("Invalid set of shares. Share indices must be unique.", "duplicate-index");
            xs[shares[i].x] = true;
            if (len === null) len = shares[i].data.length;
            else if (len !== shares[i].data.length) throw Slip39Error("Invalid set of shares. All share values must have the same length.", "length-mismatch");
        }
        for (i = 0; i < shares.length; i++) {
            if (shares[i].x === x) return shares[i].data.slice();
        }

        var logProd = 0;
        for (i = 0; i < shares.length; i++) logProd += LOG[shares[i].x ^ x];

        var result = new Uint8Array(len);
        for (i = 0; i < shares.length; i++) {
            var sum = 0;
            for (j = 0; j < shares.length; j++) {
                if (j !== i) sum += LOG[shares[i].x ^ shares[j].x];
            }
            var logBasis = ((logProd - LOG[shares[i].x ^ x] - sum) % 255 + 255) % 255;
            var d = shares[i].data;
            for (var k = 0; k < len; k++) {
                if (d[k] !== 0) result[k] ^= EXP[(LOG[d[k]] + logBasis) % 255];
            }
        }
        return result;
    }

    function createDigest(randomData, sharedSecret) {
        return hmacSha256(randomData, sharedSecret).then(function (h) { return h.slice(0, DIGEST_LENGTH_BYTES); });
    }

    function splitSecret(threshold, shareCount, secret) {
        return Promise.resolve().then(function () {
            if (threshold < 1) throw Slip39Error("The requested threshold must be a positive integer.", "scheme");
            if (threshold > shareCount) throw Slip39Error("The requested threshold must not exceed the number of shares.", "scheme");
            if (shareCount > MAX_SHARE_COUNT) throw Slip39Error("The requested number of shares must not exceed " + MAX_SHARE_COUNT + ".", "scheme");

            var i;
            if (threshold === 1) {
                var same = [];
                for (i = 0; i < shareCount; i++) same.push({ x: i, data: secret.slice() });
                return same;
            }

            var randomShareCount = threshold - 2;
            var shares = [];
            for (i = 0; i < randomShareCount; i++) shares.push({ x: i, data: randomBytes(secret.length) });

            var randomPart = randomBytes(secret.length - DIGEST_LENGTH_BYTES);
            return createDigest(randomPart, secret).then(function (digest) {
                var base = shares.concat([
                    { x: DIGEST_INDEX, data: concatBytes(digest, randomPart) },
                    { x: SECRET_INDEX, data: secret }
                ]);
                for (var j = randomShareCount; j < shareCount; j++) {
                    shares.push({ x: j, data: interpolate(base, j) });
                }
                return shares;
            });
        });
    }

    // Resolves to the secret, or rejects with code "digest".
    function recoverSecret(threshold, shares) {
        return Promise.resolve().then(function () {
            if (threshold === 1) return shares[0].data.slice();
            var secret = interpolate(shares, SECRET_INDEX);
            var digestShare = interpolate(shares, DIGEST_INDEX);
            var digest = digestShare.slice(0, DIGEST_LENGTH_BYTES);
            var randomPart = digestShare.slice(DIGEST_LENGTH_BYTES);
            return createDigest(randomPart, secret).then(function (d) {
                if (!bytesEqual(d, digest)) throw Slip39Error("Invalid digest of the shared secret.", "digest");
                return secret;
            });
        });
    }

    // ---------- Feistel encryption of the master secret ----------

    function getSalt(identifier, extendable) {
        if (extendable) return new Uint8Array(0);
        return concatBytes(asciiBytes(CS_ORIG), new Uint8Array([(identifier >>> 8) & 0xff, identifier & 0xff]));
    }

    // onRound(doneRounds, totalRounds) is called after each PBKDF2 round.
    function feistel(input, passphrase, iterationExponent, identifier, extendable, rounds, onRound) {
        if (input.length % 2 !== 0) throw Slip39Error("The length of the master secret in bytes must be an even number.", "length");
        var pass = typeof passphrase === "string" ? asciiBytes(passphrase) : (passphrase || new Uint8Array(0));
        var half = input.length / 2;
        var l = input.slice(0, half), r = input.slice(half);
        var salt = getSalt(identifier, extendable);
        var iterations = (BASE_ITERATION_COUNT << iterationExponent) / ROUND_COUNT;
        var step = 0;
        var chain = Promise.resolve();
        rounds.forEach(function (i) {
            chain = chain.then(function () {
                return pbkdf2Sha256(concatBytes(new Uint8Array([i]), pass), concatBytes(salt, r), iterations, half);
            }).then(function (f) {
                var nl = r;
                r = xorBytes(l, f);
                l = nl;
                step++;
                if (onRound) onRound(step, rounds.length);
            });
        });
        return chain.then(function () { return concatBytes(r, l); });
    }

    function encrypt(masterSecret, passphrase, iterationExponent, identifier, extendable, onRound) {
        return Promise.resolve().then(function () {
            return feistel(masterSecret, passphrase, iterationExponent, identifier, extendable, [0, 1, 2, 3], onRound);
        });
    }

    function decrypt(ems, passphrase, iterationExponent, identifier, extendable, onRound) {
        return Promise.resolve().then(function () {
            return feistel(ems, passphrase, iterationExponent, identifier, extendable, [3, 2, 1, 0], onRound);
        });
    }

    // ---------- Generating shares ----------

    function randomIdentifier() {
        var b = randomBytes(2);
        return ((b[0] << 8) | b[1]) & ((1 << ID_LENGTH_BITS) - 1);
    }

    function validateScheme(groupThreshold, groups) {
        if (!groups || !groups.length) throw Slip39Error("Add at least one group.", "scheme");
        if (groups.length > MAX_SHARE_COUNT) throw Slip39Error("At most " + MAX_SHARE_COUNT + " groups are allowed.", "scheme");
        if (!(groupThreshold >= 1)) throw Slip39Error("The group threshold must be at least 1.", "scheme");
        if (groupThreshold > groups.length) throw Slip39Error("The requested group threshold must not exceed the number of groups.", "scheme");
        groups.forEach(function (g, i) {
            var t = g[0], n = g[1];
            var label = "Group " + (i + 1) + ": ";
            if (!(n >= 1) || n > MAX_SHARE_COUNT) throw Slip39Error(label + "the number of shares must be between 1 and " + MAX_SHARE_COUNT + ".", "scheme");
            if (!(t >= 1) || t > n) throw Slip39Error(label + "the threshold must be between 1 and the number of shares.", "scheme");
            if (t === 1 && n > 1) {
                throw Slip39Error(label + "creating multiple member shares with member threshold 1 is not allowed. " +
                    "Use 1-of-1 member sharing instead (and copy that share if you need duplicates).", "scheme");
            }
        });
    }

    // ems: { identifier, extendable, iterationExponent, ciphertext }
    // groups: [[memberThreshold, memberCount], ...]
    function splitEms(groupThreshold, groups, ems) {
        return Promise.resolve().then(function () {
            if (ems.ciphertext.length * 8 < MIN_STRENGTH_BITS) {
                throw Slip39Error("The length of the master secret must be at least " + (MIN_STRENGTH_BITS / 8) + " bytes.", "length");
            }
            if (ems.ciphertext.length % 2 !== 0) throw Slip39Error("The length of the master secret in bytes must be an even number.", "length");
            validateScheme(groupThreshold, groups);
            return splitSecret(groupThreshold, groups.length, ems.ciphertext);
        }).then(function (groupShares) {
            return Promise.all(groups.map(function (g, gi) {
                return splitSecret(g[0], g[1], groupShares[gi].data).then(function (memberShares) {
                    var params = {
                        identifier: ems.identifier, extendable: ems.extendable, iterationExponent: ems.iterationExponent,
                        groupIndex: groupShares[gi].x, groupThreshold: groupThreshold, groupCount: groups.length,
                        memberThreshold: g[0]
                    };
                    return memberShares.map(function (ms) { return makeShare(params, ms.x, ms.data); });
                });
            }));
        });
    }

    // opts: { groupThreshold, groups, masterSecret (Uint8Array), passphrase, extendable, iterationExponent, identifier, onRound }
    function generateShares(opts) {
        return Promise.resolve().then(function () {
            var ms = opts.masterSecret;
            if (ms.length * 8 < MIN_STRENGTH_BITS) throw Slip39Error("The master secret must be at least 128 bits (16 bytes).", "length");
            if (ms.length % 2 !== 0) throw Slip39Error("The master secret length must be a multiple of 16 bits (an even number of bytes).", "length");
            var e = opts.iterationExponent == null ? 1 : opts.iterationExponent;
            if (!(e >= 0 && e <= 15)) throw Slip39Error("The iteration exponent must be between 0 and 15.", "exponent");
            var ext = opts.extendable !== false;
            var id = opts.identifier == null ? randomIdentifier() : opts.identifier;
            if (!(id >= 0 && id < 32768)) throw Slip39Error("The identifier must be between 0 and 32767.", "identifier");
            validateScheme(opts.groupThreshold, opts.groups);
            var pass = asciiBytes(opts.passphrase || "");
            return encrypt(ms, pass, e, id, ext, opts.onRound).then(function (ct) {
                var ems = { identifier: id, extendable: ext, iterationExponent: e, ciphertext: ct };
                return splitEms(opts.groupThreshold, opts.groups, ems).then(function (groups) {
                    return { ems: ems, groups: groups };
                });
            });
        });
    }

    // ---------- Combining shares (strict, as the reference implementation) ----------

    function decodeMnemonics(mnemonics) {
        var shares = mnemonics.map(decodeShare);
        var keys = {};
        shares.forEach(function (s) { keys[commonKey(s)] = true; });
        if (Object.keys(keys).length !== 1) {
            throw Slip39Error("Invalid set of mnemonics. All mnemonics must begin with the same " + ID_EXP_LENGTH_WORDS +
                " words, must have the same group threshold and the same group count.", "mismatch");
        }
        var groups = new Map();
        shares.forEach(function (s) {
            var g = groups.get(s.groupIndex);
            if (!g) { g = []; groups.set(s.groupIndex, g); }
            if (g.length && g[0].memberThreshold !== s.memberThreshold) {
                throw Slip39Error("Invalid set of mnemonics. The member_threshold parameters don't match.", "mismatch");
            }
            // identical shares count once (the reference keeps a set)
            if (!g.some(function (o) { return o.memberIndex === s.memberIndex && bytesEqual(o.value, s.value); })) g.push(s);
        });
        return groups;
    }

    function recoverEms(groups) {
        return Promise.resolve().then(function () {
            if (!groups.size) throw Slip39Error("The set of shares is empty.", "empty");
            var first = groups.values().next().value[0];
            if (groups.size < first.groupThreshold) {
                throw Slip39Error("Insufficient number of mnemonic groups. The required number of groups is " + first.groupThreshold + ".", "insufficient");
            }
            if (groups.size !== first.groupThreshold) {
                throw Slip39Error("Wrong number of mnemonic groups. Expected " + first.groupThreshold + " groups, but " + groups.size + " were provided.", "groups");
            }
            var list = [];
            groups.forEach(function (g, gi) {
                if (g.length !== g[0].memberThreshold) {
                    throw Slip39Error("Wrong number of mnemonics. Expected " + g[0].memberThreshold + " mnemonics starting with \"" +
                        g[0].words.slice(0, GROUP_PREFIX_LENGTH_WORDS).join(" ") + " ...\", but " + g.length + " were provided.", "insufficient");
                }
                list.push({ gi: gi, shares: g });
            });
            return Promise.all(list.map(function (item) {
                return recoverSecret(item.shares[0].memberThreshold, item.shares.map(function (s) { return { x: s.memberIndex, data: s.value }; }))
                    .then(function (sec) { return { x: item.gi, data: sec }; });
            })).then(function (groupShares) {
                return recoverSecret(first.groupThreshold, groupShares);
            }).then(function (ct) {
                return { identifier: first.identifier, extendable: first.extendable, iterationExponent: first.iterationExponent, ciphertext: ct };
            });
        });
    }

    function combineMnemonics(mnemonics, passphrase) {
        return Promise.resolve().then(function () {
            if (!mnemonics || !mnemonics.length) throw Slip39Error("The list of mnemonics is empty.", "empty");
            return recoverEms(decodeMnemonics(mnemonics));
        }).then(function (ems) {
            return decrypt(ems.ciphertext, asciiBytes(passphrase || ""), ems.iterationExponent, ems.identifier, ems.extendable);
        });
    }

    // ---------- Flexible recovery for the UI ----------

    // Classifies already-decoded shares into one share set. Shares that do not
    // match the first share's common parameters are reported, not used.
    function analyzeShares(shares) {
        var out = { params: null, groups: new Map(), mismatched: [], duplicates: [], conflicts: [], complete: false, completeGroups: 0 };
        if (!shares.length) return out;
        var ref = shares[0];
        var key = commonKey(ref);
        out.params = {
            identifier: ref.identifier, extendable: ref.extendable, iterationExponent: ref.iterationExponent,
            groupThreshold: ref.groupThreshold, groupCount: ref.groupCount, valueBytes: ref.value.length
        };
        shares.forEach(function (s, idx) {
            if (commonKey(s) !== key) { out.mismatched.push({ share: s, idx: idx, reason: mismatchReason(ref, s) }); return; }
            var g = out.groups.get(s.groupIndex);
            if (!g) {
                g = { groupIndex: s.groupIndex, memberThreshold: s.memberThreshold, members: [], thresholdConflicts: [] };
                out.groups.set(s.groupIndex, g);
            }
            if (s.memberThreshold !== g.memberThreshold) { g.thresholdConflicts.push({ share: s, idx: idx }); return; }
            var same = g.members.filter(function (m) { return m.share.memberIndex === s.memberIndex; })[0];
            if (same) {
                if (bytesEqual(same.share.value, s.value)) out.duplicates.push({ share: s, idx: idx });
                else out.conflicts.push({ share: s, idx: idx, other: same.idx });
                return;
            }
            g.members.push({ share: s, idx: idx });
        });
        out.groups.forEach(function (g) {
            g.complete = g.members.length >= g.memberThreshold;
            if (g.complete) out.completeGroups++;
        });
        out.complete = out.completeGroups >= out.params.groupThreshold;
        return out;
    }

    function mismatchReason(a, b) {
        if (a.identifier !== b.identifier) return "different identifier (another share set)";
        if (a.extendable !== b.extendable) return "different extendable flag";
        if (a.iterationExponent !== b.iterationExponent) return "different iteration exponent";
        if (a.groupThreshold !== b.groupThreshold) return "different group threshold";
        if (a.groupCount !== b.groupCount) return "different group count";
        if (a.value.length !== b.value.length) return "different length (" + b.words.length + " vs " + a.words.length + " words)";
        return "different parameters";
    }

    function combinations(n, k, limit, fn) {
        // Calls fn(indexArray) for each k-subset of 0..n-1 until fn returns true or `limit` subsets were tried.
        var idx = [], count = 0, i;
        for (i = 0; i < k; i++) idx.push(i);
        while (true) {
            if (count++ >= limit) return false;
            if (fn(idx.slice())) return true;
            for (i = k - 1; i >= 0 && idx[i] === n - k + i; i--) { /* find position to bump */ }
            if (i < 0) return false;
            idx[i]++;
            for (var j = i + 1; j < k; j++) idx[j] = idx[j - 1] + 1;
        }
    }

    // Recovers a group (or the top level) secret from >= threshold raw shares.
    // Tries other subsets when the digest fails, and reports the shares that
    // are not consistent with the polynomial that was found.
    function recoverSecretRobust(threshold, raw, subsetLimit) {
        var n = raw.length;
        if (threshold === 1) {
            var bad1 = raw.filter(function (r) { return !bytesEqual(r.data, raw[0].data); }).map(function (r) { return r.x; });
            return Promise.resolve({ secret: raw[0].data.slice(), used: [raw[0].x], inconsistent: bad1, tried: 1 });
        }
        var subsets = [];
        combinations(n, threshold, subsetLimit || 4096, function (ix) { subsets.push(ix); return false; });
        var k = 0;
        function next() {
            if (k >= subsets.length) {
                return Promise.reject(Slip39Error(subsets.length > 1
                    ? "Invalid digest for every combination of " + threshold + " shares that was tried (" + subsets.length + "). The shares are corrupted or do not belong together."
                    : "Invalid digest of the shared secret. The shares are corrupted or do not belong together.", "digest"));
            }
            var subset = subsets[k++].map(function (i) { return raw[i]; });
            return recoverSecret(threshold, subset).then(function (secret) {
                var inconsistent = raw.filter(function (r) {
                    if (subset.indexOf(r) !== -1) return false;
                    return !bytesEqual(interpolate(subset, r.x), r.data);
                }).map(function (r) { return r.x; });
                return { secret: secret, used: subset.map(function (r) { return r.x; }), inconsistent: inconsistent, tried: k };
            }, function (err) {
                if (err && err.code === "digest") return next();
                throw err;
            });
        }
        return next();
    }

    // Recovers the encrypted master secret from an analyzeShares() result,
    // tolerating surplus shares and surplus groups.
    function recoverEmsFlexible(analysis) {
        return Promise.resolve().then(function () {
            if (!analysis.params) throw Slip39Error("No valid shares were provided.", "empty");
            if (!analysis.complete) throw Slip39Error("Not enough shares yet to recover the secret.", "insufficient");
            var complete = [];
            analysis.groups.forEach(function (g) { if (g.complete) complete.push(g); });
            complete.sort(function (a, b) { return a.groupIndex - b.groupIndex; });
            var report = { groups: [] };
            return Promise.all(complete.map(function (g) {
                var raw = g.members.map(function (m) { return { x: m.share.memberIndex, data: m.share.value }; });
                return recoverSecretRobust(g.memberThreshold, raw).then(function (r) {
                    report.groups.push({ groupIndex: g.groupIndex, used: r.used, inconsistent: r.inconsistent, ok: true });
                    return { x: g.groupIndex, data: r.secret };
                }, function (err) {
                    report.groups.push({ groupIndex: g.groupIndex, ok: false, error: err.message });
                    return null;
                });
            })).then(function (groupSecrets) {
                var good = groupSecrets.filter(Boolean);
                var gt = analysis.params.groupThreshold;
                if (good.length < gt) {
                    var failed = report.groups.filter(function (r) { return !r.ok; })[0];
                    throw Slip39Error(failed ? "Group " + (failed.groupIndex + 1) + ": " + failed.error : "Not enough recoverable groups.", "digest");
                }
                return recoverSecretRobust(gt, good).then(function (r) {
                    report.usedGroups = r.used;
                    report.inconsistentGroups = r.inconsistent;
                    return {
                        identifier: analysis.params.identifier,
                        extendable: analysis.params.extendable,
                        iterationExponent: analysis.params.iterationExponent,
                        groupThreshold: gt,
                        groupCount: analysis.params.groupCount,
                        ciphertext: r.secret,
                        groupSecrets: good,
                        report: report
                    };
                });
            });
        });
    }

    // ---------- Regenerating shares ----------

    // From >= T member shares of one group, the share for any member index of
    // that group (0-15) is fully determined — it reproduces the original share
    // exactly when that index was part of the set.
    function regenerateMemberShare(groupShares, memberIndex) {
        return Promise.resolve().then(function () {
            var s0 = groupShares[0];
            var raw = groupShares.map(function (s) { return { x: s.memberIndex, data: s.value }; });
            return recoverSecretRobust(s0.memberThreshold, raw).then(function (r) {
                var value = s0.memberThreshold === 1 ? r.secret
                    : interpolate(raw.filter(function (x) { return r.used.indexOf(x.x) !== -1; }), memberIndex);
                return makeShare(s0, memberIndex, value);
            });
        });
    }

    // Recreates the group secret of `groupIndex` from enough other groups and
    // splits it into a fresh member set. With a 1-of-1 group that reproduces
    // the original share exactly; with T > 1 the new member shares form a new
    // polynomial and do NOT combine with surviving shares of that group.
    function regenerateGroup(emsInfo, groupIndex, memberThreshold, memberCount) {
        return Promise.resolve().then(function () {
            validateScheme(1, [[memberThreshold, memberCount]]);
            var gt = emsInfo.groupThreshold;
            var used = emsInfo.report && emsInfo.report.usedGroups;
            var known = used ? emsInfo.groupSecrets.filter(function (g) { return used.indexOf(g.x) !== -1; })
                : emsInfo.groupSecrets.slice(0, gt);
            var groupSecret = gt === 1 ? emsInfo.ciphertext.slice() : interpolate(known, groupIndex);
            return splitSecret(memberThreshold, memberCount, groupSecret).then(function (members) {
                var params = {
                    identifier: emsInfo.identifier, extendable: emsInfo.extendable, iterationExponent: emsInfo.iterationExponent,
                    groupIndex: groupIndex, groupThreshold: gt, groupCount: emsInfo.groupCount, memberThreshold: memberThreshold
                };
                return members.map(function (m) { return makeShare(params, m.x, m.data); });
            });
        });
    }

    // ---------- RS1024 erasure decoding (word repair) ----------

    // polymod() is affine over GF(2) in the bits of its inputs, so the words
    // at known-unknown positions can be solved for with Gaussian elimination.
    // RS1024 is MDS with 3 check symbols: up to 3 erasures are always uniquely
    // recoverable. Returns the list of solved index arrays (0 or 1 entries).
    function solveErasures(values, extendable) {
        var unk = [];
        values.forEach(function (v, i) { if (v === null || v === undefined) unk.push(i); });
        if (unk.length > 3) throw Slip39Error("At most 3 unknown words can be recovered from the checksum.", "too-many");
        var cs = csCodes(extendable);
        var base = values.map(function (v) { return v == null ? 0 : v; });
        if (!unk.length) return polymod(cs.concat(base)) === 1 ? [base] : [];

        var f0 = polymod(cs.concat(base));
        var pivots = {};
        var nvars = unk.length * 10;
        for (var v = 0; v < nvars; v++) {
            var tmp = base.slice();
            tmp[unk[(v / 10) | 0]] = 1 << (v % 10);
            var vec = polymod(cs.concat(tmp)) ^ f0;
            var mask = 1 << v;
            for (var bit = 29; bit >= 0 && vec; bit--) {
                if (!((vec >>> bit) & 1)) continue;
                if (pivots[bit]) { vec ^= pivots[bit].vec; mask ^= pivots[bit].mask; }
                else { pivots[bit] = { vec: vec, mask: mask }; vec = 0; }
            }
        }
        var t = f0 ^ 1, m = 0;
        for (var b = 29; b >= 0; b--) {
            if (!((t >>> b) & 1)) continue;
            if (!pivots[b]) return [];
            t ^= pivots[b].vec;
            m ^= pivots[b].mask;
        }
        if (t !== 0) return [];
        var sol = base.slice();
        unk.forEach(function (pos, u) { sol[pos] = (m >>> (u * 10)) & 1023; });
        return [sol];
    }

    // Tries both customization strings when the word carrying the extendable
    // bit (word 2) is itself unknown, and keeps structurally valid results.
    function solveAndValidate(values) {
        var exts = values[1] == null ? [false, true] : [((values[1] >>> 4) & 1) === 1];
        var out = [];
        exts.forEach(function (ext) {
            solveErasures(values, ext).forEach(function (sol) {
                if ((((sol[1] >>> 4) & 1) === 1) !== ext) return;
                var r = inspectIndices(sol);
                if (r.ok) out.push(sol);
            });
        });
        return out;
    }

    // Suggests corrections for a damaged share. `entries` is resolveWords()
    // output; unresolvable words and "?" are treated as erasures.
    // opts.deep adds the two-wrong-words search (can yield false matches).
    function repairCandidates(entries, opts) {
        opts = opts || {};
        var values = entries.map(function (e) { return e.index; });
        var erasures = [];
        values.forEach(function (v, i) { if (v == null) erasures.push(i); });
        var seen = {}, out = [];
        function add(sol, kind, positions) {
            var key = sol.join(",");
            if (seen[key] || key === values.join(",")) return;
            seen[key] = true;
            out.push({ indices: sol, words: indicesToWords(sol), kind: kind, positions: positions });
        }
        function trySolve(vals, kind, positions) {
            solveAndValidate(vals).forEach(function (sol) { add(sol, kind, positions); });
        }
        var n = values.length;
        var i, j;

        if (erasures.length > 3) {
            return { candidates: [], note: "More than 3 words are unknown — the checksum can recover at most 3." };
        }
        if (erasures.length) {
            trySolve(values, "erasure", erasures.slice());
            // Unknown words plus one wrong (but valid-looking) word elsewhere
            if (!out.length && erasures.length <= 2) {
                for (i = 0; i < n; i++) {
                    if (values[i] == null) continue;
                    var v1 = values.slice(); v1[i] = null;
                    trySolve(v1, "erasure+substitution", erasures.concat([i]));
                }
            }
            // Maybe a word is missing or extra next to the gaps
            if (!out.length && erasures.length <= 2) {
                for (i = 0; i <= n; i++) {
                    var ins = values.slice(0, i).concat([null], values.slice(i));
                    trySolve(ins, "erasure+missing", erasures.map(function (e) { return e >= i ? e + 1 : e; }).concat([i]));
                }
            }
            return { candidates: out };
        }

        if (inspectIndices(values).ok) return { candidates: [], valid: true };

        // 1. one wrong word
        for (i = 0; i < n; i++) {
            var vs = values.slice(); vs[i] = null;
            trySolve(vs, "substitution", [i]);
        }
        // 2. two adjacent words swapped
        for (i = 0; i + 1 < n; i++) {
            if (values[i] === values[i + 1]) continue;
            var sw = values.slice(); sw[i] = values[i + 1]; sw[i + 1] = values[i];
            if (inspectIndices(sw).ok) add(sw, "transposition", [i, i + 1]);
        }
        // 3. one word missing
        for (i = 0; i <= n; i++) {
            trySolve(values.slice(0, i).concat([null], values.slice(i)), "missing", [i]);
        }
        // 4. one extra word
        for (i = 0; i < n; i++) {
            var del = values.slice(0, i).concat(values.slice(i + 1));
            if (inspectIndices(del).ok) add(del, "extra", [i]);
        }
        // 5. (optional) two wrong words — 30 check bits vs 20 unknown bits, so
        //    roughly one false match per ~1000 position pairs.
        if (opts.deep && !out.length) {
            for (i = 0; i < n; i++) {
                for (j = i + 1; j < n; j++) {
                    var v2 = values.slice(); v2[i] = null; v2[j] = null;
                    trySolve(v2, "double-substitution", [i, j]);
                }
            }
        }
        return { candidates: out };
    }

    return {
        WORDLIST: WORDLIST,
        WORD_INDEX: WORD_INDEX,
        MIN_MNEMONIC_LENGTH_WORDS: MIN_MNEMONIC_LENGTH_WORDS,
        GROUP_PREFIX_LENGTH_WORDS: GROUP_PREFIX_LENGTH_WORDS,
        BASE_ITERATION_COUNT: BASE_ITERATION_COUNT,
        MAX_SHARE_COUNT: MAX_SHARE_COUNT,

        bytesToHex: bytesToHex,
        hexToBytes: hexToBytes,
        asciiBytes: asciiBytes,
        bytesEqual: bytesEqual,
        randomBytes: function (n) { return randomBytes(n); },
        _setRandomSource: function (fn) { randomBytes = fn; },

        tokenize: tokenize,
        resolveWords: resolveWords,
        suggestWords: suggestWords,
        editDistance: editDistance,
        mnemonicToIndices: mnemonicToIndices,
        indicesToWords: indicesToWords,
        validLengthWords: validLengthWords,

        rs1024Polymod: polymod,
        rs1024CreateChecksum: rs1024CreateChecksum,
        rs1024VerifyChecksum: rs1024VerifyChecksum,

        inspectIndices: inspectIndices,
        decodeShare: decodeShare,
        encodeShare: encodeShare,
        makeShare: makeShare,

        interpolate: interpolate,
        splitSecret: splitSecret,
        recoverSecret: recoverSecret,
        encrypt: encrypt,
        decrypt: decrypt,
        randomIdentifier: randomIdentifier,
        validateScheme: validateScheme,
        splitEms: splitEms,
        generateShares: generateShares,

        decodeMnemonics: decodeMnemonics,
        recoverEms: recoverEms,
        combineMnemonics: combineMnemonics,

        analyzeShares: analyzeShares,
        recoverEmsFlexible: recoverEmsFlexible,
        regenerateMemberShare: regenerateMemberShare,
        regenerateGroup: regenerateGroup,

        solveErasures: solveErasures,
        repairCandidates: repairCandidates
    };
});
