// Minimal BIP-39 helpers for the SLIP-39 tool (English wordlist only).
//   - mnemonicToSeed: PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic" + passphrase
//   - validate: word lookup + SHA-256 checksum
//   - entropyToMnemonic: for showing a recovered 128-256 bit secret as BIP-39 words
// Uses WebCrypto; the wordlist comes from ../BIP39-checksum/bip39_english.js
// (window.bipWords) in the browser, or is passed in by the Node tests.

(function (root, factory) {
    "use strict";
    var api = factory(root);
    if (typeof module === "object" && module.exports) module.exports = api;
    root.BIP39Lite = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
    "use strict";

    function words() {
        var w = root.bipWords;
        if (!w || w.length !== 2048) throw new Error("BIP-39 English wordlist is not loaded.");
        return w;
    }

    function normalize(str) {
        return String(str || "").normalize("NFKD");
    }

    function splitWords(mnemonic) {
        return normalize(mnemonic).toLowerCase().trim().split(/\s+/).filter(Boolean);
    }

    function utf8(str) {
        return new TextEncoder().encode(str);
    }

    function sha256(bytes) {
        return root.crypto.subtle.digest("SHA-256", bytes).then(function (h) { return new Uint8Array(h); });
    }

    // Returns { ok, words, entropy, error }
    function validate(mnemonic) {
        var list = words();
        var ws = splitWords(mnemonic);
        if ([12, 15, 18, 21, 24].indexOf(ws.length) === -1) {
            return Promise.resolve({ ok: false, words: ws, error: "A BIP-39 mnemonic has 12, 15, 18, 21 or 24 words (got " + ws.length + ")." });
        }
        var bad = ws.filter(function (w) { return list.indexOf(w) === -1; });
        if (bad.length) {
            return Promise.resolve({ ok: false, words: ws, error: "Not in the BIP-39 English wordlist: " + bad.slice(0, 5).join(", ") + (bad.length > 5 ? " …" : "") + "." });
        }
        var bits = ws.map(function (w) { var b = list.indexOf(w).toString(2); return "00000000000".slice(b.length) + b; }).join("");
        var csLen = ws.length / 3;
        var entBits = bits.slice(0, bits.length - csLen);
        var entropy = new Uint8Array(entBits.length / 8);
        for (var i = 0; i < entropy.length; i++) entropy[i] = parseInt(entBits.substr(i * 8, 8), 2);
        return sha256(entropy).then(function (h) {
            var hb = "";
            for (var j = 0; j < Math.ceil(csLen / 8); j++) { var x = h[j].toString(2); hb += "00000000".slice(x.length) + x; }
            var ok = hb.slice(0, csLen) === bits.slice(bits.length - csLen);
            return { ok: ok, words: ws, entropy: entropy, error: ok ? null : "The BIP-39 checksum (last word) is invalid — check for a typo." };
        });
    }

    function mnemonicToSeed(mnemonic, passphrase) {
        var m = splitWords(mnemonic).join(" ");
        var salt = utf8("mnemonic" + normalize(passphrase || ""));
        var subtle = root.crypto.subtle;
        return subtle.importKey("raw", utf8(m), "PBKDF2", false, ["deriveBits"])
            .then(function (k) { return subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt: salt, iterations: 2048 }, k, 512); })
            .then(function (b) { return new Uint8Array(b); });
    }

    // entropy: 16, 20, 24, 28 or 32 bytes
    function entropyToMnemonic(entropy) {
        var list = words();
        if ([16, 20, 24, 28, 32].indexOf(entropy.length) === -1) return Promise.resolve(null);
        return sha256(entropy).then(function (h) {
            var bits = "";
            var i;
            for (i = 0; i < entropy.length; i++) { var b = entropy[i].toString(2); bits += "00000000".slice(b.length) + b; }
            var csLen = entropy.length * 8 / 32;
            var hb = "";
            for (i = 0; i < Math.ceil(csLen / 8); i++) { var x = h[i].toString(2); hb += "00000000".slice(x.length) + x; }
            bits += hb.slice(0, csLen);
            var out = [];
            for (i = 0; i < bits.length; i += 11) out.push(list[parseInt(bits.substr(i, 11), 2)]);
            return out.join(" ");
        });
    }

    return { validate: validate, mnemonicToSeed: mnemonicToSeed, entropyToMnemonic: entropyToMnemonic, splitWords: splitWords };
});
