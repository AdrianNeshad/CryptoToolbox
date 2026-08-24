// script.js — Magic Tool
// Klistra in valfri text, verktyget skannar och klassificerar allt
// kryptorelaterat innehåll den hittar (nycklar, adresser, entropy,
// plånboks-krypteringsmetadata, generiska kodningar).
//
// Konfidensnivåer (färgkodas i UI:t och förklaras i legenden):
//   verified — checksumma/struktur kryptografiskt kontrollerad (grön)
//   invalid  — formatet gör anspråk på checksumma men den stämmer inte (röd)
//   likely   — formatet stämmer men kan inte verifieras (blå)
//   unknown  — kodad data utan igenkänt format (gul)

var input = document.getElementById("input");
var clearButton = document.getElementById("clear-button");
var testdataButton = document.getElementById("testdata-button");
var resultsEl = document.getElementById("results");
var legendEl = document.getElementById("legend");
var emptyState = document.getElementById("empty-state");
var emptyStateText = emptyState.querySelector("p");
var emptyStateDefaultText = emptyStateText.textContent;
var resultCount = document.getElementById("result-count");
var toast = document.getElementById("toast");

var CH = window.CryptoHelpers;

// ---------- Konfidensnivåer ----------

var CONFIDENCE_ORDER = ["verified", "likely", "unknown", "invalid"];

var CONFIDENCE_META = {
    verified: {
        rank: 0,
        chipClass: "chip-verified",
        dotClass: "dot-verified",
        legend: "Verifierad - checksumma korrekt eller struktur kryptografiskt kontrollerad"
    },
    likely: {
        rank: 2,
        chipClass: "chip-likely",
        dotClass: "dot-likely",
        legend: "Möjlig träff - formatet stämmer men kan inte verifieras"
    },
    unknown: {
        rank: 3,
        chipClass: "chip-unknown",
        dotClass: "dot-unknown",
        legend: "Okänd - kodad data utan igenkänt format"
    },
    invalid: {
        rank: 1,
        chipClass: "chip-invalid",
        dotClass: "dot-invalid",
        legend: "Felaktig - formatet stämmer men checksumman är fel"
    }
};

// ---------- Referenstabeller ----------

var ADDRESS_VERSIONS = {
    0x00: "Bitcoin-adress (Legacy P2PKH, mainnet)",
    0x05: "Bitcoin-adress (P2SH, mainnet)",
    0x6f: "Bitcoin-adress (Legacy P2PKH, testnet)",
    0xc4: "Bitcoin-adress (P2SH, testnet)",
    0x30: "Litecoin-adress (Legacy P2PKH, mainnet)",
    0x32: "Litecoin-adress (P2SH, mainnet)",
    0x1e: "Dogecoin-adress (P2PKH, mainnet)",
    0x16: "Dogecoin-adress (P2SH, mainnet)",
    0x4c: "Dash-adress (P2PKH, mainnet)",
    0x10: "Dash-adress (P2SH, mainnet)",
    0x41: "Tron-adress (TRC10/TRC20)"
};

var WIF_VERSIONS = {
    0x80: "Privat nyckel (WIF, Bitcoin mainnet)",
    0xef: "Privat nyckel (WIF, Bitcoin testnet)",
    0xb0: "Privat nyckel (WIF, Litecoin mainnet)",
    0x9e: "Privat nyckel (WIF, Dogecoin mainnet)",
    0xcc: "Privat nyckel (WIF, Dash mainnet)"
};

// Zcash transparenta adresser använder 2-byte-versioner (payload 22 byte).
var TWO_BYTE_ADDRESS_VERSIONS = {
    "1cb8": "Zcash-adress (transparent, P2PKH)",
    "1cbd": "Zcash-adress (transparent, P2SH)"
};

var EXTENDED_KEY_VERSIONS = {
    "0488b21e": "Utökad publik nyckel — xpub (BIP32 Legacy, mainnet)",
    "0488ade4": "Utökad privat nyckel — xprv (BIP32 Legacy, mainnet)",
    "049d7cb2": "Utökad publik nyckel — ypub (BIP49 SegWit-i-P2SH, mainnet)",
    "049d7878": "Utökad privat nyckel — yprv (BIP49 SegWit-i-P2SH, mainnet)",
    "04b24746": "Utökad publik nyckel — zpub (BIP84 Native SegWit, mainnet)",
    "04b2430c": "Utökad privat nyckel — zprv (BIP84 Native SegWit, mainnet)",
    "043587cf": "Utökad publik nyckel — tpub (BIP32, testnet)",
    "04358394": "Utökad privat nyckel — tprv (BIP32, testnet)",
    "044a5262": "Utökad publik nyckel — upub (BIP49, testnet)",
    "044a4e28": "Utökad privat nyckel — uprv (BIP49, testnet)",
    "045f1cf6": "Utökad publik nyckel — vpub (BIP84, testnet)",
    "045f18bc": "Utökad privat nyckel — vprv (BIP84, testnet)"
};

var BECH32_HRP_NAMES = {
    bc: "Bitcoin", tb: "Bitcoin (testnet)", bcrt: "Bitcoin (regtest)",
    ltc: "Litecoin", tltc: "Litecoin (testnet)",
    cosmos: "Cosmos Hub (ATOM)", osmo: "Osmosis", akash: "Akash",
    juno: "Juno", celestia: "Celestia", axelar: "Axelar", secret: "Secret Network",
    inj: "Injective", stars: "Stargaze", kava: "Kava"
};

var MONERO_NETWORKS = {
    18: "Monero-adress (mainnet, standard)",
    19: "Monero-adress (mainnet, integrated)",
    42: "Monero-adress (mainnet, subadress)",
    53: "Monero-adress (testnet, standard)",
    54: "Monero-adress (testnet, integrated)",
    63: "Monero-adress (testnet, subadress)",
    24: "Monero-adress (stagenet, standard)",
    25: "Monero-adress (stagenet, integrated)",
    36: "Monero-adress (stagenet, subadress)"
};

// Algoritm-nyckelord, ordnade specifik → generell. Varje träff maskeras i
// arbetstexten så att generellare mönster inte dubbelrapporterar samma
// förekomst (t.ex. "aes-256" inuti "aes-256-gcm", "sha512" inuti "hmac-sha512").
var ALGO_KEYWORDS = [
    // — Chiffer —
    { re: /\baes-?256-?gcm\b/gi, label: "AES-256-GCM (AEAD-chiffer)" },
    { re: /\baes-?256-?cbc\b/gi, label: "AES-256-CBC (chiffer)" },
    { re: /\baes-?256-?ctr\b/gi, label: "AES-256-CTR (chiffer)" },
    { re: /\baes-?192-?(?:gcm|cbc|ctr)\b/gi, label: "AES-192 (chiffer)" },
    { re: /\baes-?128-?gcm\b/gi, label: "AES-128-GCM (AEAD-chiffer)" },
    { re: /\baes-?128-?cbc\b/gi, label: "AES-128-CBC (chiffer)" },
    { re: /\baes-?128-?ctr\b/gi, label: "AES-128-CTR (chiffer)" },
    { re: /\bxchacha20-?poly1305\b/gi, label: "XChaCha20-Poly1305 (AEAD-chiffer)" },
    { re: /\bchacha20-?poly1305\b/gi, label: "ChaCha20-Poly1305 (AEAD-chiffer)" },
    { re: /\bxchacha20\b/gi, label: "XChaCha20 (strömchiffer)" },
    { re: /\bchacha20\b/gi, label: "ChaCha20 (strömchiffer)" },
    { re: /\bxsalsa20\b/gi, label: "XSalsa20 (strömchiffer)" },
    { re: /\bsalsa20\b/gi, label: "Salsa20 (strömchiffer)" },
    { re: /\baes-?256\b/gi, label: "AES-256 (chiffer, läge ospecificerat)" },
    { re: /\baes-?192\b/gi, label: "AES-192 (chiffer, läge ospecificerat)" },
    { re: /\baes-?128\b/gi, label: "AES-128 (chiffer, läge ospecificerat)" },
    { re: /\btwofish\b/gi, label: "Twofish (chiffer)" },
    { re: /\bblowfish\b/gi, label: "Blowfish (chiffer, äldre)" },
    { re: /\bcamellia\b/gi, label: "Camellia (chiffer)" },
    { re: /\b(?:3des|triple-?des|des-?ede3?)\b/gi, label: "3DES (chiffer, föråldrat)" },
    { re: /\brc4\b/gi, label: "RC4 (strömchiffer, osäkert)" },

    // — Nyckelderivering / lösenordshash —
    { re: /\bargon2(?:id|i|d)?\b/gi, label: "Argon2 (nyckelderivering)" },
    { re: /\bpbkdf2(?:[-_](?:hmac[-_])?sha-?(?:1|256|512))?\b/gi, label: "PBKDF2 (nyckelderivering)" },
    { re: /\bscrypt\b/gi, label: "scrypt (nyckelderivering)" },
    { re: /\bbcrypt\b/gi, label: "bcrypt (lösenordshash)" },
    { re: /\bhkdf\b/gi, label: "HKDF (nyckelderivering)" },

    // — MAC —
    { re: /\bhmac(?:-?(?:sha-?(?:1|224|256|384|512)|md5))?\b/gi, label: "HMAC (meddelandeautentisering)" },
    { re: /\bpoly1305\b/gi, label: "Poly1305 (MAC)" },

    // — Hashfunktioner —
    { re: /\bkeccak-?(?:224|256|384|512)?\b/gi, label: "Keccak (hashfunktion)" },
    { re: /\bsha3-?(?:224|256|384|512)?\b/gi, label: "SHA-3 (hashfunktion)" },
    { re: /\bblake2[bs]?\b/gi, label: "BLAKE2 (hashfunktion)" },
    { re: /\bblake3\b/gi, label: "BLAKE3 (hashfunktion)" },
    { re: /\bripemd-?160\b/gi, label: "RIPEMD-160 (hashfunktion)" },
    { re: /\bsha-?512\b/gi, label: "SHA-512 (hashfunktion)" },
    { re: /\bsha-?384\b/gi, label: "SHA-384 (hashfunktion)" },
    { re: /\bsha-?256\b/gi, label: "SHA-256 (hashfunktion)" },
    { re: /\bsha-?224\b/gi, label: "SHA-224 (hashfunktion)" },
    { re: /\bsha-?1\b/gi, label: "SHA-1 (hashfunktion, föråldrad)" },
    { re: /\bmd5\b/gi, label: "MD5 (hashfunktion, osäker)" },

    // — Kurvor, signaturer & nyckelutbyte —
    { re: /\bed25519\b/gi, label: "Ed25519 (signaturalgoritm)" },
    { re: /\bed448\b/gi, label: "Ed448 (signaturalgoritm)" },
    { re: /\bx25519\b/gi, label: "X25519 (nyckelutbyte)" },
    { re: /\bcurve25519\b/gi, label: "Curve25519 (elliptisk kurva)" },
    { re: /\bsecp256k1\b/gi, label: "secp256k1 (elliptisk kurva — Bitcoin/Ethereum)" },
    { re: /\b(?:secp256r1|prime256v1|nist-?p-?256)\b/gi, label: "P-256/secp256r1 (elliptisk kurva)" },
    { re: /\becdsa\b/gi, label: "ECDSA (signaturalgoritm)" },
    { re: /\beddsa\b/gi, label: "EdDSA (signaturalgoritm)" },
    { re: /\bschnorr\b/gi, label: "Schnorr (signaturalgoritm)" },
    { re: /\brsa(?:-?(?:1024|2048|3072|4096))?\b/gi, label: "RSA (asymmetrisk kryptering)" }
];

var WALLET_JSON_FIELDS = ["ciphertext", "iv", "salt", "mac"];

var BIP38_VERSIONS = {
    "0142": "BIP38-krypterad privat nyckel (icke EC-multiplicerad)",
    "0143": "BIP38-krypterad privat nyckel (EC-multiplicerad)"
};

var BIP39_WORDLIST = (window.entropyWordlists && window.entropyWordlists.bip39) || [];
var BIP39_LENGTHS = { 12: true, 15: true, 18: true, 21: true, 24: true };

// Electrum-seedfraser versioneras med HMAC-SHA512("Seed version", fras):
// hex-prefixet på resultatet anger plånbokstypen. Mest specifika prefix först.
var ELECTRUM_VERSIONS = [
    { prefix: "100", name: "segwit" },
    { prefix: "101", name: "2FA" },
    { prefix: "102", name: "2FA segwit" },
    { prefix: "01", name: "standard" }
];

// ---------- Hjälpfunktioner ----------

function bytesToHex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
}

function hexToDecimalList(hex) {
    var parts = [];
    for (var i = 0; i < hex.length; i += 2) parts.push(parseInt(hex.slice(i, i + 2), 16));
    return parts.join(",");
}

function isEntropyObjectShape(node, keys) {
    if (keys.length !== 16 && keys.length !== 32) return false;
    for (var i = 0; i < keys.length; i++) {
        if (keys.indexOf(String(i)) === -1) return false;
        var v = node[String(i)];
        if (!Number.isInteger(v) || v < 0 || v > 255) return false;
    }
    return true;
}

// Base64url → avkodad UTF-8-sträng, eller null om avkodningen misslyckas.
function base64UrlToString(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    var bin;
    try { bin = atob(b64); } catch (e) { return null; }
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (e) {
        return null;
    }
}

// ---------- Helhetstext-pass ----------

function walkJson(node, addFinding) {
    if (node === null || node === undefined) return;
    if (Array.isArray(node)) {
        node.forEach(function (item) { walkJson(item, addFinding); });
        return;
    }
    if (typeof node === "object") {
        var keys = Object.keys(node);

        if (isEntropyObjectShape(node, keys)) {
            var bytes = [];
            for (var bi = 0; bi < keys.length; bi++) bytes.push(node[String(bi)]);
            var hex = bytesToHex(bytes);
            addFinding(hex, "Entropy (" + bytes.length + " byte, JSON-objekt)", "verified",
                { label: "Decimal", value: bytes.join(",") });
        }

        // Ethereum Keystore V3: strukturen är specifik nog att känna igen direkt
        // (version 3 + crypto.cipher/crypto.ciphertext) istället för att bara
        // rapportera de enskilda cipher/kdf-fälten var för sig. Använder samma
        // "value" som ciphertext-fältet nedan så de två träffarna slås ihop till
        // ett kort.
        if (node.version === 3 && node.crypto && typeof node.crypto === "object" &&
            typeof node.crypto.cipher === "string" && typeof node.crypto.ciphertext === "string") {
            addFinding(node.crypto.ciphertext, "Ethereum Keystore V3 (nyckelfil)", "verified");
        }

        keys.forEach(function (key) {
            var value = node[key];
            var lowerKey = key.toLowerCase();

            if ((lowerKey === "kdf" || lowerKey === "cipher") && typeof value === "string") {
                addFinding(value, "Krypteringsfält \"" + key + "\": " + value, "verified");
            }
            if (WALLET_JSON_FIELDS.indexOf(lowerKey) !== -1 && typeof value === "string" && value.length >= 8) {
                addFinding(value, "Plånboksfält \"" + key + "\" (" + Math.floor(value.length / 2) + " byte hex)", "verified");
            }

            walkJson(value, addFinding);
        });
    }
}

// Hittar toppnivå-{...}/[...]-block var som helst i texten (inte bara om HELA
// texten är giltig JSON) genom att matcha ihop klamrar och hoppa över citerade
// strängar, så JSON som klistrats in tillsammans med annan text ändå fångas.
function findJsonBlocks(text) {
    var blocks = [];
    for (var i = 0; i < text.length; i++) {
        var ch = text[i];
        if (ch === "{" || ch === "[") {
            var end = findMatchingBracket(text, i);
            if (end !== -1) {
                blocks.push(text.slice(i, end + 1));
                i = end;
            }
        }
    }
    return blocks;
}

function findMatchingBracket(text, start) {
    var open = text[start];
    var close = open === "{" ? "}" : "]";
    var depth = 0;
    var inString = false;
    var stringChar = null;
    var escape = false;

    for (var i = start; i < text.length; i++) {
        var ch = text[i];
        if (inString) {
            if (escape) escape = false;
            else if (ch === "\\") escape = true;
            else if (ch === stringChar) inString = false;
            continue;
        }
        if (ch === '"' || ch === "'") {
            inString = true;
            stringChar = ch;
            continue;
        }
        if (ch === open) depth++;
        else if (ch === close) {
            depth--;
            if (depth === 0) return i;
        }
    }
    return -1;
}

// Parsar varje funnet JSON-block: giltig syntax rapporteras som ett verifierat
// fynd, och innehållet genomsöks rekursivt efter plånboksfält/entropy.
function scanJsonBlocks(text, addFinding) {
    findJsonBlocks(text).forEach(function (block) {
        var parsed;
        try {
            parsed = JSON.parse(block);
        } catch (e) {
            // blocket var inte giltig JSON (t.ex. bara en kod-snutt med klamrar) —
            // nyckelords- och token-passen fångar ändå upp relevant innehåll i det
            return;
        }
        if (!parsed || typeof parsed !== "object") return;

        var count = Array.isArray(parsed) ? parsed.length : Object.keys(parsed).length;
        if (count > 0 && block.length >= 20) {
            var desc = Array.isArray(parsed)
                ? "Giltig JSON-array (" + count + " element)"
                : "Giltigt JSON-objekt (" + count + (count === 1 ? " nyckel" : " nycklar") + ")";
            addFinding(block.trim(), desc + " · syntax verifierad", "verified");
        }
        walkJson(parsed, addFinding);
    });
}

function scanAlgorithmKeywords(text, addFinding, consumed) {
    var work = text;
    ALGO_KEYWORDS.forEach(function (kw) {
        kw.re.lastIndex = 0;
        var m;
        while ((m = kw.re.exec(work)) !== null) {
            addFinding(m[0], kw.label, "likely");
            consumed.add(m[0]);
            // maskera träffen så generellare mönster inte matchar samma text igen
            work = work.slice(0, m.index) + " ".repeat(m[0].length) + work.slice(m.index + m[0].length);
        }
    });
}

function scanEntropyLists(text, addFinding) {
    // Negativ lookbehind/lookahead så en talrad inte "äter" en angränsande siffra
    // som egentligen hör till ett hex/base58-ord precis före eller efter (t.ex.
    // sista tecknet i en 0x-adress som råkar sluta på en siffra).
    var re = /(?<![0-9a-zA-Z])\[?\s*\d{1,3}(?:\s*[,\s]\s*\d{1,3})*\s*\]?(?![0-9a-zA-Z])/g;
    var m;
    while ((m = re.exec(text)) !== null) {
        var raw = m[0];
        var nums = raw.replace(/[[\]]/g, "").trim().split(/[,\s]+/).filter(function (s) { return s.length > 0; }).map(Number);
        var validCount = nums.length === 16 || nums.length === 32;
        var validBytes = nums.every(function (n) { return Number.isInteger(n) && n >= 0 && n <= 255; });
        if (validCount && validBytes) {
            addFinding(raw.trim(), "Entropy (" + nums.length + " byte, talista)", "likely",
                { label: "Hex", value: bytesToHex(nums) });
        }
    }
}

function scanDerivationPaths(text, addFinding) {
    // t.ex. m/44'/0'/0'/0/0 eller m/84h/0h/0h/0/0 (h/' markerar hardened index)
    var re = /\bm(?:\/\d+[h']?)+/g;
    var m;
    while ((m = re.exec(text)) !== null) {
        addFinding(m[0], "BIP32 derivation path", "likely");
    }
}

// JWT: tre base64url-delar separerade med punkter. Headern avkodas och parsas
// som JSON — lyckas det (och innehåller "alg") är identifieringen verifierad.
function scanJwtTokens(text, addFinding, consumed) {
    var re = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{10,}\b/g;
    var m;
    while ((m = re.exec(text)) !== null) {
        var parts = m[0].split(".");
        var headerStr = base64UrlToString(parts[0]);
        if (!headerStr) continue;
        var header;
        try { header = JSON.parse(headerStr); } catch (e) { continue; }
        if (!header || typeof header.alg !== "string") continue;

        var payloadStr = base64UrlToString(parts[1]);
        var payloadOk = false;
        if (payloadStr) {
            try { JSON.parse(payloadStr); payloadOk = true; } catch (e) { /* ej JSON */ }
        }

        var label = "JWT (alg: " + header.alg + (typeof header.typ === "string" ? ", typ: " + header.typ : "") + ") · header avkodad och parsad";
        addFinding(m[0], label, "verified",
            payloadOk ? { label: "Payload", value: payloadStr } : undefined);
        parts.forEach(function (p) { consumed.add(p); });
    }
}

// PEM-block: BEGIN/END-huvuden med base64-innehåll emellan. Matchande huvuden
// + giltig base64 som avkodas till DER (0x30-prefix) räknas som verifierad
// struktur. Returnerar texten med funna block bortmaskerade, så att
// nyckelordsskanningen inte reagerar på t.ex. "RSA" i huvudet.
function scanPemBlocks(text, addFinding, consumed) {
    var masked = text;
    var re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
    var m;
    while ((m = re.exec(text)) !== null) {
        var type = m[1];
        var body = m[2].replace(/\s/g, "");
        var validB64 = body.length > 0 && body.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(body);

        if (validB64) {
            var derNote = "";
            try {
                var decoded = atob(body);
                if (decoded.length > 0 && decoded.charCodeAt(0) === 0x30) derNote = ", DER-struktur";
            } catch (e) {
                validB64 = false;
            }
            if (validB64) {
                addFinding(m[0].trim(),
                    "PEM-block: " + type + " (~" + Math.floor(body.length * 3 / 4) + " byte" + derNote + ") · struktur verifierad",
                    "verified");
                m[2].split(/\s+/).forEach(function (line) {
                    if (line.length >= 8) consumed.add(line);
                });
            }
        }
        if (!validB64) {
            addFinding(m[0].trim(), "PEM-block: " + type + " (ogiltig/ofullständig base64)", "likely");
        }
        masked = masked.slice(0, m.index) + " ".repeat(m[0].length) + masked.slice(m.index + m[0].length);
    }
    return masked;
}

// CashAddr med explicit prefix ("bitcoincash:q..."). Prefixet ingår i
// polymod-checksumman, så en träff är fullt verifierad — och ett uttryckligt
// prefix med felaktig checksumma är ett tydligt fel värt att flagga.
function scanCashAddr(text, addFinding, consumed) {
    var re = /\b(bitcoincash|bchtest|bchreg):([qpzry9x8gf2tvdw0s3jn54khce6mua7l]{34,112})\b/gi;
    var m;
    while ((m = re.exec(text)) !== null) {
        var prefix = m[1].toLowerCase();
        var net = prefix === "bitcoincash" ? "mainnet" : (prefix === "bchtest" ? "testnet" : "regtest");
        var decoded = CH.decodeCashAddr(prefix, m[2]);
        if (decoded) {
            var type = describeCashAddrType(decoded.versionByte);
            addFinding(m[0], "Bitcoin Cash-adress (" + type + ", " + net + ") · checksumma verifierad", "verified");
            consumed.add(m[2]);
        } else {
            addFinding(m[0], "Bitcoin Cash-adress (" + net + ") — checksumman stämmer INTE", "invalid");
        }
    }
}

function describeCashAddrType(versionByte) {
    var type = versionByte >> 3;
    if (type === 0) return "P2PKH";
    if (type === 1) return "P2SH";
    return "typ " + type;
}

// ---------- BIP39/Electrum mnemonic-fraser ----------

function bytesToBinaryLocal(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(2).padStart(8, "0");
    return s;
}

function binaryToBytesLocal(bits) {
    var bytes = [];
    for (var i = 0; i < bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return bytes;
}

// Avkodar orden tillbaka till bitar och räknar om SHA-256-checksumman från
// entropy-delen, samma metod som Entropy2Mnemonic-verktyget använder — så en
// hittad fras verifieras kryptografiskt istället för att bara matchas mot
// ordlistan.
async function verifyBip39Checksum(words) {
    var bits = words.map(function (w) {
        return BIP39_WORDLIST.indexOf(w).toString(2).padStart(11, "0");
    }).join("");

    var totalBits = bits.length;
    var checksumBitLength = totalBits / 33;
    var entropyBitLength = totalBits - checksumBitLength;

    var entropyBits = bits.slice(0, entropyBitLength);
    var embeddedChecksumBits = bits.slice(entropyBitLength);

    var entropyBytes = new Uint8Array(binaryToBytesLocal(entropyBits));
    var hash = await CH.sha256(entropyBytes);
    var recomputedChecksumBits = bytesToBinaryLocal(Array.from(hash)).slice(0, checksumBitLength);

    return recomputedChecksumBits === embeddedChecksumBits;
}

// Electrum-seedfraser har ingen BIP39-checksumma; istället är frasen giltig om
// HMAC-SHA512("Seed version", fras) börjar på ett känt versionsprefix.
async function checkElectrumVersion(words) {
    var mac = await CH.hmacSha512("Seed version", words.join(" "));
    var hex = bytesToHex(mac);
    for (var i = 0; i < ELECTRUM_VERSIONS.length; i++) {
        if (hex.indexOf(ELECTRUM_VERSIONS[i].prefix) === 0) return ELECTRUM_VERSIONS[i].name;
    }
    return null;
}

// Samlar runs av ordlisteord i en textsnutt. Ett run bryts av ord som inte
// finns i BIP39-listan; bara run med giltig fraslängd (12/15/18/21/24) blir
// kandidater.
function collectMnemonicCandidates(str, wordSet) {
    var candidates = [];
    var re = /[A-Za-z]+/g;
    var m;
    var run = [];
    var runStart = -1;
    var lastEnd = 0;

    function flushRun(endPos) {
        if (run.length && BIP39_LENGTHS[run.length]) {
            candidates.push({ words: run.slice(), phrase: str.slice(runStart, endPos).trim() });
        }
        run = [];
        runStart = -1;
    }

    while ((m = re.exec(str)) !== null) {
        var word = m[0].toLowerCase();
        if (wordSet.has(word)) {
            if (run.length === 0) runStart = m.index;
            run.push(word);
            lastEnd = re.lastIndex;
        } else {
            flushRun(lastEnd);
        }
    }
    flushRun(lastEnd);
    return candidates;
}

async function scanMnemonicPhrases(text, addFinding) {
    if (!BIP39_WORDLIST.length) return;
    var wordSet = new Set(BIP39_WORDLIST);

    // Pass 1 — radvis: två fraser på angränsande rader får inte smälta ihop
    // till en enda ogiltig jättekandidat.
    var candidates = [];
    text.split("\n").forEach(function (line) {
        collectMnemonicCandidates(line, wordSet).forEach(function (c) { candidates.push(c); });
    });

    for (var i = 0; i < candidates.length; i++) {
        var c = candidates[i];
        if (await verifyBip39Checksum(c.words)) {
            addFinding(c.phrase, "BIP39 mnemonic-fras (" + c.words.length + " ord) · checksumma verifierad", "verified");
            continue;
        }
        var electrumType = await checkElectrumVersion(c.words);
        if (electrumType) {
            addFinding(c.phrase, "Electrum-seedfras (" + electrumType + ", " + c.words.length + " ord) · versionsprefix verifierad", "verified");
        } else {
            addFinding(c.phrase, c.words.length + " ord från BIP39-listan — ingen giltig BIP39/Electrum-checksumma", "likely");
        }
    }

    // Pass 2 — över radbrytningar (t.ex. seedfraser skrivna med ett ord per
    // rad). För att inte skapa brus av run som råkat smälta ihop rapporteras
    // radöverskridande kandidater bara när frasen faktiskt verifierar.
    var crossCandidates = collectMnemonicCandidates(text, wordSet);
    for (var j = 0; j < crossCandidates.length; j++) {
        var cc = crossCandidates[j];
        if (cc.phrase.indexOf("\n") === -1) continue; // redan täckt av pass 1
        if (await verifyBip39Checksum(cc.words)) {
            addFinding(cc.phrase, "BIP39 mnemonic-fras (" + cc.words.length + " ord, flerradig) · checksumma verifierad", "verified");
            continue;
        }
        var crossElectrum = await checkElectrumVersion(cc.words);
        if (crossElectrum) {
            addFinding(cc.phrase, "Electrum-seedfras (" + crossElectrum + ", " + cc.words.length + " ord, flerradig) · versionsprefix verifierad", "verified");
        }
    }
}

// ---------- Token-pass ----------

function classifyBase58Payload(payload) {
    var labels = [];
    if (payload.length === 78) {
        var version = bytesToHex(payload.slice(0, 4));
        if (EXTENDED_KEY_VERSIONS[version]) labels.push(EXTENDED_KEY_VERSIONS[version]);
    } else if (payload.length === 33 || payload.length === 34) {
        var v = payload[0];
        if (WIF_VERSIONS[v]) {
            var suffix = payload.length === 34
                ? (payload[33] === 0x01 ? " · komprimerad" : " · okänt suffix")
                : " · okomprimerad";
            labels.push(WIF_VERSIONS[v] + suffix);
        }
    } else if (payload.length === 21) {
        var v2 = payload[0];
        if (ADDRESS_VERSIONS[v2]) labels.push(ADDRESS_VERSIONS[v2]);
    } else if (payload.length === 22) {
        var v4 = bytesToHex(payload.slice(0, 2));
        if (TWO_BYTE_ADDRESS_VERSIONS[v4]) labels.push(TWO_BYTE_ADDRESS_VERSIONS[v4]);
    } else if (payload.length === 39) {
        var v3 = bytesToHex(payload.slice(0, 2));
        if (BIP38_VERSIONS[v3]) labels.push(BIP38_VERSIONS[v3]);
    }
    return labels;
}

function describeBech32(decoded) {
    var chainName = BECH32_HRP_NAMES[decoded.hrp] || decoded.hrp;
    if (decoded.witnessVersion !== null) {
        if (decoded.witnessVersion === 0) {
            var kind = decoded.program.length === 20 ? "P2WPKH" : (decoded.program.length === 32 ? "P2WSH" : "SegWit v0");
            return chainName + "-adress (Native SegWit, " + kind + ")";
        }
        if (decoded.witnessVersion === 1) {
            return chainName + "-adress (Taproot)";
        }
        return chainName + "-adress (SegWit v" + decoded.witnessVersion + ")";
    }
    return "Bech32-adress (" + chainName + ", " + decoded.program.length + " byte)";
}

// Publika nycklar i hex. Okomprimerade (04 + x + y) kan verifieras starkt:
// punkten måste ligga på secp256k1-kurvan (en slumpsträng klarar det med
// ~2^-256 sannolikhet). Komprimerade (02/03 + x) kan bara delvis kontrolleras —
// men om x INTE ligger på kurvan är det bevisat att det inte är en giltig
// secp256k1-nyckel, vilket halverar mängden falska positiver.
function classifyPublicKeyHex(value, hexPart, addFinding) {
    if (hexPart.length === 66 && /^0[23]/.test(hexPart)) {
        if (CH.hasValidSecp256k1X(hexPart.slice(2))) {
            addFinding(value, "Komprimerad publik nyckel (secp256k1, x-koordinaten ligger på kurvan)", "likely");
        } else {
            addFinding(value, "Möjlig komprimerad publik nyckel (x ej på secp256k1 — annan kurva?)", "likely");
        }
        return true;
    }
    if (hexPart.length === 130 && /^04/.test(hexPart)) {
        if (CH.isPointOnSecp256k1(hexPart.slice(2, 66), hexPart.slice(66))) {
            addFinding(value, "Okomprimerad publik nyckel (secp256k1) · punkten ligger på kurvan", "verified");
        } else {
            addFinding(value, "Möjlig okomprimerad publik nyckel (ej på secp256k1 — annan kurva?)", "likely");
        }
        return true;
    }
    return false;
}

function classifyRawHex(token, addFinding) {
    var len = token.length;
    if (len === 32) {
        addFinding(token, "Entropy (16 byte, hex)", "likely",
            { label: "Decimal", value: hexToDecimalList(token.toLowerCase()) });
        addFinding(token, "Möjlig MD5-hash", "likely");
        return true;
    }
    if (len === 40) {
        // Blandad case som exakt matchar EIP-55-casingen är ett kryptografiskt
        // starkt tecken på en EVM-adress som saknar sitt 0x-prefix.
        var mixed = /[a-f]/.test(token) && /[A-F]/.test(token);
        if (mixed && CH.checkEip55(token)) {
            addFinding(token, "EVM-adress utan 0x-prefix · EIP-55-checksumma verifierad", "verified");
        } else {
            addFinding(token, "Möjlig SHA-1- eller RIPEMD-160-hash", "likely");
        }
        return true;
    }
    if (len === 56) {
        addFinding(token, "Möjlig SHA-224-hash", "likely");
        return true;
    }
    if (len === 64) {
        if (CH.isValidSecp256k1Scalar(token)) {
            addFinding(token, "Möjlig privat nyckel (hex, inom secp256k1-intervallet)", "likely");
        }
        addFinding(token, "Möjlig SHA-256-hash", "likely");
        addFinding(token, "Entropy (32 byte, hex)", "likely",
            { label: "Decimal", value: hexToDecimalList(token.toLowerCase()) });
        return true;
    }
    if (classifyPublicKeyHex(token, token, addFinding)) return true;
    if (len === 96) {
        addFinding(token, "Möjlig SHA-384-hash", "likely");
        return true;
    }
    if (len === 128) {
        addFinding(token, "Möjlig BIP39-seed (64 byte, hex)", "likely");
        addFinding(token, "Möjlig SHA-512-hash", "likely");
        return true;
    }
    return false;
}

// Base64-kandidater avkodas och innehållet inspekteras: JSON blir ett
// verifierat fynd (och genomsöks), läsbar text visas avkodad, och rent binärt
// innehåll katalogiseras som okänt. Kravet på blandade teckenklasser hindrar
// vanliga ord och hex-strängar från att felflaggas som base64.
function inspectBase64(token, addFinding) {
    var isStd = token.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(token);
    var isUrl = !isStd && /^[A-Za-z0-9_-]+$/.test(token) && /[_-]/.test(token);
    if (!isStd && !isUrl) return false;

    var hasUpper = /[A-Z]/.test(token);
    var hasLower = /[a-z]/.test(token);
    var hasDigit = /[0-9]/.test(token);
    if (isStd && !/[+/=]/.test(token) && !(hasUpper && hasLower && hasDigit)) return false;
    // base64url utan tydlig signal ger många falska positiver på bindestreckade
    // ord — kräv full teckenmix och lite längd innan vi ens försöker
    if (isUrl && !(hasUpper && hasLower && hasDigit && token.length >= 22)) return false;

    var b64 = isUrl ? token.replace(/-/g, "+").replace(/_/g, "/") : token;
    while (b64.length % 4 !== 0) b64 += "=";
    var bin;
    try { bin = atob(b64); } catch (e) { return false; }
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);

    var decodedText = null;
    try { decodedText = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (e) { /* binärt */ }

    if (decodedText !== null) {
        var trimmed = decodedText.trim();
        if (trimmed[0] === "{" || trimmed[0] === "[") {
            var parsed = null;
            try { parsed = JSON.parse(trimmed); } catch (e) { /* ej JSON */ }
            if (parsed && typeof parsed === "object") {
                addFinding(token, "Base64-kodad JSON · avkodad och parsad", "verified",
                    { label: "JSON", value: trimmed });
                walkJson(parsed, addFinding);
                return true;
            }
        }
        var printable = trimmed.length > 0 && !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(decodedText);
        if (printable) {
            addFinding(token, "Base64-kodad text (" + bytes.length + " byte)", "likely",
                { label: "Text", value: trimmed.length > 300 ? trimmed.slice(0, 300) + "…" : trimmed });
            return true;
        }
    }

    var sizeNote = (bytes.length === 16 || bytes.length === 32 || bytes.length === 64)
        ? bytes.length + " byte binärt — kan vara nyckel/entropy"
        : bytes.length + " byte binärt";
    addFinding(token, "Base64-data (" + sizeNote + ")", "unknown");
    return true;
}

function genericFallback(token, addFinding) {
    if (token.length < 16) return;
    if (/^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0) {
        addFinding(token, "Hex-data (" + (token.length / 2) + " byte, okänd betydelse)", "unknown");
        return;
    }
    if (inspectBase64(token, addFinding)) return;
    // Base58 utan träff i något känt format: kräv siffror + blandad case så
    // vanliga ord inte felflaggas
    if (token.length >= 20 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(token) &&
        /[0-9]/.test(token) && /[A-Z]/.test(token) && /[a-z]/.test(token)) {
        addFinding(token, "Base58-kodad data (okänt format, ingen giltig checksumma)", "unknown");
    }
}

async function classifyToken(token, addFinding) {
    // 1. UUID (8-4-4-4-12): versions- och variantbitarna kontrolleras
    var um = token.match(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-([0-9a-fA-F])[0-9a-fA-F]{3}-([0-9a-fA-F])[0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/);
    if (um) {
        var uuidVersion = parseInt(um[1], 16);
        var variantNibble = parseInt(um[2], 16);
        if (uuidVersion >= 1 && uuidVersion <= 8 && variantNibble >= 8 && variantNibble <= 11) {
            addFinding(token, "UUID v" + uuidVersion + " (RFC 4122) · struktur verifierad", "verified");
        } else {
            addFinding(token, "UUID-liknande format (ogiltiga versions-/variantbitar)", "likely");
        }
        return;
    }

    // 2. 0x-prefixad hex (EVM-adress / privat nyckel / tx-hash / pubnyckel)
    if (/^0x[0-9a-fA-F]+$/.test(token)) {
        var hexPart = token.slice(2);
        if (hexPart.length === 40) {
            var hasLower = /[a-f]/.test(hexPart);
            var hasUpper = /[A-F]/.test(hexPart);
            if (hasLower && hasUpper) {
                if (CH.checkEip55(hexPart)) {
                    addFinding(token, "EVM-adress (Ethereum/BSC/Polygon/...) · EIP-55-checksumma verifierad", "verified");
                } else {
                    addFinding(token, "EVM-adress — EIP-55-checksumman stämmer INTE (felskriven adress?)", "invalid");
                }
            } else {
                addFinding(token, "EVM-adress (Ethereum/BSC/Polygon/...) — utan checksum-casing, kan ej verifieras", "likely");
            }
        } else if (hexPart.length === 64) {
            if (CH.isValidSecp256k1Scalar(hexPart)) {
                addFinding(token, "Möjlig privat nyckel (hex, 0x-prefix, inom secp256k1-intervallet)", "likely");
            }
            addFinding(token, "Möjlig transaktionshash", "likely");
        } else {
            classifyPublicKeyHex(token, hexPart, addFinding);
        }
        return;
    }

    // 3. TON-adress (48 tecken base64/base64url med CRC16-checksumma)
    if (token.length === 48 && /^[A-Za-z0-9+/_-]{48}$/.test(token)) {
        var ton = CH.decodeTonAddress(token);
        if (ton) {
            var tonDesc = (ton.bounceable ? "bounceable" : "ej bounceable") +
                (ton.testOnly ? ", endast test" : "") +
                ", workchain " + ton.workchain;
            addFinding(token, "TON-adress (" + tonDesc + ") · CRC16-checksumma verifierad", "verified");
            return;
        }
    }

    // 4. Bech32 / bech32m (BIP-173/350 separator-tecknet "1" saknas aldrig)
    var onePos = token.indexOf("1");
    if (onePos > 0 && onePos < token.length - 6) {
        var decoded = CH.decodeBech32Address(token);
        if (decoded) {
            addFinding(token, describeBech32(decoded) + " · checksumma verifierad", "verified");
            return;
        }
    }

    // 5. Base58check (Bitcoin-familjens adresser/nycklar, Tron, Zcash, Ripple)
    if (/^[1-9A-HJ-NP-Za-km-z]{20,120}$/.test(token)) {
        var result = await CH.base58CheckDecode(token, CH.BASE58_ALPHABET);
        if (result) {
            var labels = classifyBase58Payload(result.payload);
            if (labels.length) {
                labels.forEach(function (label) { addFinding(token, label + " · checksumma verifierad", "verified"); });
                return;
            }
        }
        if (token[0] === "r") {
            var rResult = await CH.base58CheckDecode(token, CH.RIPPLE_ALPHABET);
            if (rResult && rResult.payload.length === 21 && rResult.payload[0] === 0x00) {
                addFinding(token, "Ripple-adress (XRP) · checksumma verifierad", "verified");
                return;
            }
        }
    }

    // 6. CashAddr utan prefix (42 tecken, antaget prefix "bitcoincash")
    var lowerToken = token.toLowerCase();
    if (/^[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}$/.test(lowerToken)) {
        var cash = CH.decodeCashAddr("bitcoincash", lowerToken);
        if (cash) {
            addFinding(token, "Bitcoin Cash-adress (" + describeCashAddrType(cash.versionByte) + ", utan prefix) · checksumma verifierad", "verified");
            return;
        }
    }

    // 7. Rå hex utan 0x-prefix
    if (/^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0) {
        if (classifyRawHex(token, addFinding)) return;
    }

    // 8. Solana (rå base58 publik nyckel, formatet saknar checksumma)
    if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(token)) {
        var raw58 = CH.base58Decode(token, CH.BASE58_ALPHABET);
        if (raw58 && raw58.length === 32) {
            addFinding(token, "Möjlig Solana-adress / publik nyckel (formatet saknar checksumma)", "likely");
            return;
        }
    }

    // 9. Monero (egen base58-blockkodning, keccak-checksumman verifieras)
    if (/^[1-9A-HJ-NP-Za-km-z]{90,110}$/.test(token)) {
        var xmr = CH.decodeMoneroAddress(token);
        if (xmr) {
            var name = MONERO_NETWORKS[xmr.network] || ("Monero-liknande adress (nätbyte " + xmr.network + ")");
            addFinding(token, name + " · keccak-checksumma verifierad", "verified");
            return;
        }
    }
}

// ---------- Skanningsorkestrering ----------

async function scanText(text) {
    var findings = new Map();
    // Deltokens som redan förklarats av ett textpass (JWT-delar, PEM-rader,
    // algoritm-nyckelord, cashaddr-payloads) hoppas över i token-passet så de
    // inte dubbelrapporteras som generisk kodad data.
    var consumed = new Set();

    function addFinding(value, label, confidence, alt) {
        if (!findings.has(value)) findings.set(value, { value: value, types: [] });
        var f = findings.get(value);
        if (!f.types.some(function (t) { return t.label === label; })) {
            f.types.push({ label: label, confidence: confidence });
        }
        // Alternativ representation av samma värde (t.ex. entropy i både hex
        // och decimal) — visas som en extra rad i kortet.
        if (alt && !f.alt) f.alt = alt;
    }

    if (!text || !text.trim()) return [];

    scanJsonBlocks(text, addFinding);
    var keywordText = scanPemBlocks(text, addFinding, consumed);
    scanJwtTokens(text, addFinding, consumed);
    scanCashAddr(text, addFinding, consumed);
    scanAlgorithmKeywords(keywordText, addFinding, consumed);
    scanEntropyLists(text, addFinding);
    scanDerivationPaths(text, addFinding);
    await scanMnemonicPhrases(text, addFinding);

    var tokens = text.match(/[A-Za-z0-9+/=_-]{8,}/g) || [];
    var uniqueTokens = Array.from(new Set(tokens)).slice(0, 3000);
    for (var i = 0; i < uniqueTokens.length; i++) {
        var token = uniqueTokens[i];
        if (consumed.has(token)) continue;
        await classifyToken(token, addFinding);
        // Generisk katalogisering bara om inget pass gjorde anspråk på värdet
        if (!findings.has(token)) genericFallback(token, addFinding);
    }

    var list = Array.from(findings.values());

    // Sortera chips i varje kort och korten sinsemellan: verifierat först,
    // därefter felaktig checksumma, möjliga träffar och sist okänt.
    function rank(confidence) { return CONFIDENCE_META[confidence].rank; }
    list.forEach(function (f) {
        f.types.sort(function (a, b) { return rank(a.confidence) - rank(b.confidence); });
    });
    list.sort(function (a, b) {
        return rank(a.types[0].confidence) - rank(b.types[0].confidence);
    });

    return list;
}

// ---------- Rendering ----------

function renderCard(finding) {
    var card = document.createElement("div");
    card.className = "result-card";

    var chipRow = document.createElement("div");
    chipRow.className = "chip-row";
    finding.types.forEach(function (t) {
        var chip = document.createElement("span");
        var meta = CONFIDENCE_META[t.confidence] || CONFIDENCE_META.likely;
        chip.className = "chip " + meta.chipClass;
        chip.textContent = t.label;
        chipRow.appendChild(chip);
    });
    card.appendChild(chipRow);

    card.appendChild(buildValueRow(finding.value));
    if (finding.alt) {
        card.appendChild(buildValueRow(finding.alt.value, finding.alt.label));
    }
    return card;
}

function buildValueRow(value, formatLabel) {
    var valueRow = document.createElement("div");
    valueRow.className = "value-row";

    if (formatLabel) {
        var tag = document.createElement("span");
        tag.className = "format-tag";
        tag.textContent = formatLabel;
        valueRow.appendChild(tag);
    }

    var valueEl = document.createElement("code");
    valueEl.className = "value-text";
    valueEl.textContent = value;
    valueRow.appendChild(valueEl);

    var copyBtn = document.createElement("button");
    copyBtn.className = "copy-btn";
    copyBtn.type = "button";
    copyBtn.textContent = "Kopiera";
    copyBtn.addEventListener("click", function () {
        navigator.clipboard.writeText(value).then(function () {
            showToast("Kopierat till urklipp");
        });
    });
    valueRow.appendChild(copyBtn);

    return valueRow;
}

// Legenden visar alla färgkoder och är alltid synlig, även utan inmatad text.
function renderLegend() {
    legendEl.innerHTML = "";
    CONFIDENCE_ORDER.forEach(function (confidence) {
        var meta = CONFIDENCE_META[confidence];
        var item = document.createElement("span");
        item.className = "legend-item";
        var dot = document.createElement("span");
        dot.className = "legend-dot " + meta.dotClass;
        item.appendChild(dot);
        item.appendChild(document.createTextNode(meta.legend));
        legendEl.appendChild(item);
    });
}

function render(findings, text) {
    resultsEl.innerHTML = "";

    if (!text || !text.trim()) {
        emptyStateText.textContent = emptyStateDefaultText;
        emptyState.classList.remove("display-none");
        resultsEl.classList.add("display-none");
        resultCount.textContent = "";
        return;
    }

    if (findings.length === 0) {
        emptyStateText.textContent = "Inget kryptorelaterat innehåll hittades";
        emptyState.classList.remove("display-none");
        resultsEl.classList.add("display-none");
        resultCount.textContent = "0 träffar";
        return;
    }

    emptyState.classList.add("display-none");
    resultsEl.classList.remove("display-none");

    var verifiedCount = findings.filter(function (f) {
        return f.types.some(function (t) { return t.confidence === "verified"; });
    }).length;
    resultCount.textContent = findings.length + (findings.length === 1 ? " träff" : " träffar") +
        (verifiedCount ? " · " + verifiedCount + (verifiedCount === 1 ? " verifierad" : " verifierade") : "");

    findings.forEach(function (f) {
        resultsEl.appendChild(renderCard(f));
    });
}

function showToast(text) {
    toast.textContent = text;
    toast.classList.add("show");
    setTimeout(function () {
        toast.classList.remove("show");
    }, 2000);
}

// ---------- Testdata ----------
// Exempel som täcker alla kategorier verktyget kan klassificera, med riktiga
// checksumgiltiga nycklar/adresser — plus en avsiktligt felskriven EVM-adress
// som demonstrerar den röda "checksumma felaktig"-nivån.

var TEST_DATA = [
    "L4ToPMbLRVxUAT5eixyDS1or4aFndPXsBFpgZkLhcZhYoQUVZ512",
    "xpub67eAM7jRBcMpoEEv19tD94ZiW5kbvyquZKjgwc8s8KSakiWztUK52s8ngnVD3uv9kpb2fd5Whn7NDig6pAFthq25sptyGAEJWFf1HU88Hck",
    "THgxGZ645zJD3EHzmhSjRp1PJM57t12SLM",
    "rLbiba1Tp77oG1Qb2je8nQEmDKNbk71UUc",
    "DAhZgttE5Tg2pAKAM4WvQL8Zg69UFppyC9",
    "bc1qqlkgeswcfcytjqvvufl5afjmzxgj7phpf4eagp",
    "bc1pnnpxg5trvpng5s6rvxkuudjrzejhnn67nw2dy05ymwj73y6nz08qua60ar",
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    "cosmos14lg4my6a77w4st4vr40ss4xsq4uzdkzn7dufxr",
    "7YUg9r6ttwAB7p1uYX2CyCbNpv3X1ERSxS2yyM1eFw3o",
    "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xFB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "34,83,38,148,136,254,124,59,160,186,149,60,155,68,241,6",
    '{"version":1,"identifier":"7aec91735f7e125dde475e982aae316c88f336e361593f70a4e51c2e1c7c1dd7","name":"Account 1","entropy":{"0":34,"1":83,"2":38,"3":148,"4":136,"5":254,"6":124,"7":59,"8":160,"9":186,"10":149,"11":60,"12":155,"13":68,"14":241,"15":6}}',
    'Wallet-dump: {"crypto":{"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"n":4096},"ciphertext":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0"}} slutet av dumpen',
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "leave flee turkey only common behind sausage stamp make opinion notice sample",
    "fd01247b947310a65f45a88a350a2be833570fea82bbcb6d4d32d6e3c89d6ebc0f1922b4815fefd1d4f5ea309de4be48b1ee2c7dae63b69eeca0c7d4d5214ef2",
    "6PYQU2sX9f9JJEJwZo8S6bZcZHyVtecXPR7v6t9Zph4tCBUbwkAQ5Y1dqz",
    'Keystore: {"version":3,"id":"e0fe53d0-7a3d-4f65-88b1-9bb4e245a169","crypto":{"ciphertext":"64b5b416bb2bef882eb7cc63ed92c064e53c818ec46351e07ac140e5ba871596f1595fe6cad8333147fe68c031ba001b79b64dd1edd513043134217b7ffe1903ca23b1fbe823671827e3b2dff69bbd448d9cb79a3321ec8801f2a995","cipherparams":{"iv":"7aaf7eb6f4b0e7d995e8eac67e4d52eb"},"kdf":"scrypt","kdfparams":{"r":8,"p":6,"n":4096,"dklen":32,"salt":"80132842c6cde8f9d04582932ef92c3cad3ba6b41e1296ef681692372886db86"},"mac":"01816d0a5c31cd03b644f2d756ac8167c2498808040cbace8c35c46dcf06b7a1","cipher":"aes-128-ctr"},"address":"32dd55E0BCF509a35A3F5eEb8593fbEb244796b1"}',
    "Derivation path: m/44'/0'/0'/0/0",
    "333f226d7631860d3020432d497b4333a74edbb4709e3fdf75be0e0bea34475a",
    "23d74c7c36b814a23ea337739da22de5",
    "fb67a6394c139ae6a87ff257804157c7f5414ce9",
    "029cee1dbe6982065696889570737e2b40a4aff459736268946c6fb4b4efef3438",
    "049cee1dbe6982065696889570737e2b40a4aff459736268946c6fb4b4efef3438b36314c27d71a3228a045afcbe03fd94e6e021b2b958cffcd618c70c25410838",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "eyJrZGYiOiJhcmdvbjJpZCIsImNpcGhlciI6InhjaGFjaGEyMC1wb2x5MTMwNSIsIml0ZXJhdGlvbnMiOjN9",
    "550e8400-e29b-41d4-a716-446655440000",
    "Gt0LbTeSg9EFVayQ/H1YC/GwV+4pq95JnPA0s/D8QkI=",
].join("\n");

// ---------- Init & event-koppling ----------

var scanTimer = null;
var scanToken = 0;

function scheduleScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(runScan, 250);
}

async function runScan() {
    var myToken = ++scanToken;
    var text = input.value;
    var findings = await scanText(text);
    if (myToken !== scanToken) return; // en nyare skanning har redan startat
    render(findings, text);
}

input.addEventListener("input", scheduleScan);

clearButton.addEventListener("click", function () {
    input.value = "";
    render([], "");
    input.focus();
});

testdataButton.addEventListener("click", function () {
    input.value = TEST_DATA;
    scheduleScan();
    input.focus();
});

renderLegend();
render([], "");

// --- Temasynkronisering med Verktygslådan (postMessage från förälder-iframe) ---
window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    const data = event.data;
    if (data && data.source === 'verktygslada' && data.type === 'theme' &&
        (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignoreras */ }
    }
});
