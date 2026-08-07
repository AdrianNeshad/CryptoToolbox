// script.js — Magic Tool
// Klistra in valfri text, verktyget skannar och klassificerar allt
// kryptorelaterat innehåll den hittar (nycklar, adresser, entropy,
// plånboks-krypteringsmetadata, generiska kodningar).

var input = document.getElementById("input");
var clearButton = document.getElementById("clear-button");
var testdataButton = document.getElementById("testdata-button");
var resultsEl = document.getElementById("results");
var emptyState = document.getElementById("empty-state");
var emptyStateText = emptyState.querySelector("p");
var emptyStateDefaultText = emptyStateText.textContent;
var resultCount = document.getElementById("result-count");
var toast = document.getElementById("toast");

var CH = window.CryptoHelpers;

// ---------- Referenstabeller ----------

var ADDRESS_VERSIONS = {
    0x00: "Bitcoin-adress (Legacy P2PKH, mainnet)",
    0x05: "Bitcoin-adress (P2SH, mainnet)",
    0x6f: "Bitcoin-adress (Legacy P2PKH, testnet)",
    0xc4: "Bitcoin-adress (P2SH, testnet)",
    0x30: "Litecoin-adress (Legacy P2PKH, mainnet)",
    0x32: "Litecoin-adress (P2SH, mainnet)",
    0x41: "Tron-adress (TRC10/TRC20)"
};

var WIF_VERSIONS = {
    0x80: "Privat nyckel (WIF, Bitcoin mainnet)",
    0xef: "Privat nyckel (WIF, Bitcoin testnet)",
    0xb0: "Privat nyckel (WIF, Litecoin mainnet)"
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

var SPECIFIC_CIPHER_KEYWORDS = [
    { re: /aes-?256-?gcm/i, label: "AES-256-GCM (chiffer)" },
    { re: /aes-?256-?cbc/i, label: "AES-256-CBC (chiffer)" },
    { re: /aes-?256-?ctr/i, label: "AES-256-CTR (chiffer)" },
    { re: /aes-?128-?ctr/i, label: "AES-128-CTR (chiffer)" },
    { re: /aes-?128-?cbc/i, label: "AES-128-CBC (chiffer)" },
    { re: /aes-?128-?gcm/i, label: "AES-128-GCM (chiffer)" },
    { re: /chacha20-poly1305/i, label: "ChaCha20-Poly1305 (chiffer)" },
    { re: /chacha20/i, label: "ChaCha20 (chiffer)" },
    { re: /\bscrypt\b/i, label: "scrypt (nyckelderivering)" },
    { re: /\bpbkdf2\b/i, label: "PBKDF2 (nyckelderivering)" }
];

var GENERIC_AES_KEYWORDS = [
    { re: /\baes-?256\b/i, label: "AES-256 (chiffer, läge ospecificerat)", bits: "256" },
    { re: /\baes-?128\b/i, label: "AES-128 (chiffer, läge ospecificerat)", bits: "128" }
];

var WALLET_JSON_FIELDS = ["ciphertext", "iv", "salt", "mac"];

var BIP38_VERSIONS = {
    "0142": "BIP38-krypterad privat nyckel (icke EC-multiplicerad)",
    "0143": "BIP38-krypterad privat nyckel (EC-multiplicerad)"
};

var BIP39_WORDLIST = (window.entropyWordlists && window.entropyWordlists.bip39) || [];
var BIP39_LENGTHS = { 12: true, 15: true, 18: true, 21: true, 24: true };

// ---------- Hjälpfunktioner ----------

function bytesToHex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
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
            var bytes = keys.map(function (k) { return node[k]; });
            var hex = bytes.map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
            addFinding(hex, "Entropy (" + bytes.length + " byte, JSON-objekt)", "verified");
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

function scanCipherKeywords(text, addFinding) {
    var specificBitsFound = {};
    SPECIFIC_CIPHER_KEYWORDS.forEach(function (kw) {
        var m = text.match(kw.re);
        if (m) {
            addFinding(m[0], kw.label, "likely");
            if (/256/.test(kw.re.source)) specificBitsFound["256"] = true;
            if (/128/.test(kw.re.source)) specificBitsFound["128"] = true;
        }
    });
    GENERIC_AES_KEYWORDS.forEach(function (kw) {
        if (specificBitsFound[kw.bits]) return;
        var m = text.match(kw.re);
        if (m) addFinding(m[0], kw.label, "likely");
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
            addFinding(raw.trim(), "Entropy (" + nums.length + " byte, talista)", "likely");
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

// ---------- BIP39 mnemonic-fraser ----------

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

async function scanMnemonicPhrases(text, addFinding) {
    if (!BIP39_WORDLIST.length) return;
    var wordSet = new Set(BIP39_WORDLIST);

    var candidates = [];
    var re = /[A-Za-z]+/g;
    var m;
    var run = [];
    var runStart = -1;
    var lastEnd = 0;

    function flushRun(endPos) {
        if (run.length && BIP39_LENGTHS[run.length]) {
            candidates.push({ words: run.slice(), phrase: text.slice(runStart, endPos).trim() });
        }
        run = [];
        runStart = -1;
    }

    while ((m = re.exec(text)) !== null) {
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

    for (var i = 0; i < candidates.length; i++) {
        var c = candidates[i];
        var valid = await verifyBip39Checksum(c.words);
        if (valid) {
            addFinding(c.phrase, "BIP39 mnemonic-fras (" + c.words.length + " ord) · checksum verifierad", "verified");
        } else {
            addFinding(c.phrase, c.words.length + " ord från BIP39-listan hittade", "likely");
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

function classifyRawHex(token, addFinding) {
    var len = token.length;
    if (len === 32) {
        addFinding(token, "Entropy (16 byte, hex)", "likely");
        addFinding(token, "Möjlig MD5-hash", "likely");
        return true;
    }
    if (len === 40) {
        addFinding(token, "Möjlig SHA-1- eller RIPEMD-160-hash", "likely");
        return true;
    }
    if (len === 64) {
        addFinding(token, "Möjlig privat nyckel (hex)", "likely");
        addFinding(token, "Möjlig SHA-256-hash", "likely");
        addFinding(token, "Entropy (32 byte, hex)", "likely");
        return true;
    }
    if (len === 66 && /^0[23]/.test(token)) {
        addFinding(token, "Komprimerad publik nyckel (hex)", "likely");
        return true;
    }
    if (len === 130 && /^04/.test(token)) {
        addFinding(token, "Okomprimerad publik nyckel (hex)", "likely");
        return true;
    }
    if (len === 128) {
        addFinding(token, "Möjlig BIP39-seed (64 byte, hex)", "likely");
        return true;
    }
    return false;
}

function genericFallback(token, addFinding) {
    if (token.length < 16) return;
    if (/^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0) {
        addFinding(token, "Hex-data (" + (token.length / 2) + " byte)", "likely");
        return;
    }
    if (/^[A-Za-z0-9+/]+=*$/.test(token) && token.length % 4 === 0) {
        addFinding(token, "Base64-kodad data (~" + Math.floor((token.length * 3) / 4) + " byte)", "likely");
        return;
    }
    if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(token)) {
        addFinding(token, "Base58-kodad data (okänt format)", "likely");
    }
}

async function classifyToken(token, addFinding) {
    // 1. 0x-prefixad hex (EVM-adress / privat nyckel / tx-hash)
    if (/^0x[0-9a-fA-F]+$/.test(token)) {
        var hexPart = token.slice(2);
        if (hexPart.length === 40) {
            var mixedCase = /[a-f]/.test(hexPart) && /[A-F]/.test(hexPart);
            addFinding(token, "EVM-adress (Ethereum/BSC/Polygon/...)" + (mixedCase ? " — blandad case (checksum-format, ej verifierad)" : ""), "likely");
        } else if (hexPart.length === 64) {
            addFinding(token, "Möjlig privat nyckel (hex, 0x-prefix)", "likely");
            addFinding(token, "Möjlig transaktionshash", "likely");
        }
        return;
    }

    // 2. Bech32 / bech32m (BIP-173/350 separator-tecknet "1" saknas aldrig)
    var onePos = token.indexOf("1");
    if (onePos > 0 && onePos < token.length - 6) {
        var decoded = CH.decodeBech32Address(token);
        if (decoded) {
            addFinding(token, describeBech32(decoded), "verified");
            return;
        }
    }

    // 3. Base58check (Bitcoin-familjens adresser/nycklar, Tron, Ripple)
    if (/^[1-9A-HJ-NP-Za-km-z]{20,120}$/.test(token)) {
        var result = await CH.base58CheckDecode(token, CH.BASE58_ALPHABET);
        if (result) {
            var labels = classifyBase58Payload(result.payload);
            if (labels.length) {
                labels.forEach(function (label) { addFinding(token, label, "verified"); });
                return;
            }
        }
        if (token[0] === "r") {
            var rResult = await CH.base58CheckDecode(token, CH.RIPPLE_ALPHABET);
            if (rResult && rResult.payload.length === 21 && rResult.payload[0] === 0x00) {
                addFinding(token, "Ripple-adress (XRP)", "verified");
                return;
            }
        }
    }

    // 4. Rå hex utan 0x-prefix
    if (/^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0) {
        if (classifyRawHex(token, addFinding)) return;
    }

    // 5. Solana (rå base58 publik nyckel, ingen checksum i formatet)
    if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(token)) {
        var raw58 = CH.base58Decode(token, CH.BASE58_ALPHABET);
        if (raw58 && raw58.length === 32) {
            addFinding(token, "Möjlig Solana-adress / publik nyckel (ej checksum-verifierbar)", "likely");
            return;
        }
    }

    // 6. Monero (egen base58-blockkodning, checksum verifieras ej i v1)
    if (/^[48][1-9A-HJ-NP-Za-km-z]{89,109}$/.test(token)) {
        addFinding(token, "Möjlig Monero-adress (ej checksum-verifierad)", "likely");
        return;
    }

    // 7. Generisk katalogisering av oklassificerad kodad data
    genericFallback(token, addFinding);
}

// ---------- Skanningsorkestrering ----------

async function scanText(text) {
    var findings = new Map();

    function addFinding(value, label, confidence) {
        if (!findings.has(value)) findings.set(value, { value: value, types: [] });
        var f = findings.get(value);
        if (!f.types.some(function (t) { return t.label === label; })) {
            f.types.push({ label: label, confidence: confidence });
        }
    }

    if (!text || !text.trim()) return [];

    findJsonBlocks(text).forEach(function (block) {
        try {
            walkJson(JSON.parse(block), addFinding);
        } catch (e) {
            // blocket var inte giltig JSON (t.ex. bara en kod-snutt med klamrar) —
            // nyckelords- och token-passen fångar ändå upp relevant innehåll i det
        }
    });

    scanCipherKeywords(text, addFinding);
    scanEntropyLists(text, addFinding);
    scanDerivationPaths(text, addFinding);
    await scanMnemonicPhrases(text, addFinding);

    var tokens = text.match(/[A-Za-z0-9+/=_-]{8,}/g) || [];
    var uniqueTokens = Array.from(new Set(tokens)).slice(0, 3000);
    for (var i = 0; i < uniqueTokens.length; i++) {
        await classifyToken(uniqueTokens[i], addFinding);
    }

    return Array.from(findings.values());
}

// ---------- Rendering ----------

function renderCard(finding) {
    var card = document.createElement("div");
    card.className = "result-card";

    var chipRow = document.createElement("div");
    chipRow.className = "chip-row";
    finding.types.forEach(function (t) {
        var chip = document.createElement("span");
        chip.className = "chip " + (t.confidence === "verified" ? "chip-verified" : "chip-likely");
        chip.textContent = t.label;
        chipRow.appendChild(chip);
    });
    card.appendChild(chipRow);

    var valueRow = document.createElement("div");
    valueRow.className = "value-row";

    var valueEl = document.createElement("code");
    valueEl.className = "value-text";
    valueEl.textContent = finding.value;
    valueRow.appendChild(valueEl);

    var copyBtn = document.createElement("button");
    copyBtn.className = "copy-btn";
    copyBtn.type = "button";
    copyBtn.textContent = "Kopiera";
    copyBtn.addEventListener("click", function () {
        navigator.clipboard.writeText(finding.value).then(function () {
            showToast("Kopierat till urklipp");
        });
    });
    valueRow.appendChild(copyBtn);

    card.appendChild(valueRow);
    return card;
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
    resultCount.textContent = findings.length + (findings.length === 1 ? " träff" : " träffar");

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
// Samma exempelblock som visas i dokumentationen — täcker alla kategorier
// verktyget kan klassificera, med riktiga checksumgiltiga nycklar/adresser.

var TEST_DATA = [
    "L4ToPMbLRVxUAT5eixyDS1or4aFndPXsBFpgZkLhcZhYoQUVZ512",
    "xpub67eAM7jRBcMpoEEv19tD94ZiW5kbvyquZKjgwc8s8KSakiWztUK52s8ngnVD3uv9kpb2fd5Whn7NDig6pAFthq25sptyGAEJWFf1HU88Hck",
    "THgxGZ645zJD3EHzmhSjRp1PJM57t12SLM",
    "rLbiba1Tp77oG1Qb2je8nQEmDKNbk71UUc",
    "bc1qqlkgeswcfcytjqvvufl5afjmzxgj7phpf4eagp",
    "bc1pnnpxg5trvpng5s6rvxkuudjrzejhnn67nw2dy05ymwj73y6nz08qua60ar",
    "cosmos14lg4my6a77w4st4vr40ss4xsq4uzdkzn7dufxr",
    "7YUg9r6ttwAB7p1uYX2CyCbNpv3X1ERSxS2yyM1eFw3o",
    "0x71C7656EC7ab88b098defB751B7401B5f6d89760",
    "34,83,38,148,136,254,124,59,160,186,149,60,155,68,241,6",
    '{"version":1,"identifier":"7aec91735f7e125dde475e982aae316c88f336e361593f70a4e51c2e1c7c1dd7","name":"Account 1","entropy":{"0":34,"1":83,"2":38,"3":148,"4":136,"5":254,"6":124,"7":59,"8":160,"9":186,"10":149,"11":60,"12":155,"13":68,"14":241,"15":6}}',
    'Wallet-dump: {"crypto":{"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"n":4096},"ciphertext":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0"}} slutet av dumpen',
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "fd01247b947310a65f45a88a350a2be833570fea82bbcb6d4d32d6e3c89d6ebc0f1922b4815fefd1d4f5ea309de4be48b1ee2c7dae63b69eeca0c7d4d5214ef2",
    "6PYQU2sX9f9JJEJwZo8S6bZcZHyVtecXPR7v6t9Zph4tCBUbwkAQ5Y1dqz",
    'Keystore: {"version":3,"id":"e0fe53d0-7a3d-4f65-88b1-9bb4e245a169","crypto":{"ciphertext":"64b5b416bb2bef882eb7cc63ed92c064e53c818ec46351e07ac140e5ba871596f1595fe6cad8333147fe68c031ba001b79b64dd1edd513043134217b7ffe1903ca23b1fbe823671827e3b2dff69bbd448d9cb79a3321ec8801f2a995","cipherparams":{"iv":"7aaf7eb6f4b0e7d995e8eac67e4d52eb"},"kdf":"scrypt","kdfparams":{"r":8,"p":6,"n":4096,"dklen":32,"salt":"80132842c6cde8f9d04582932ef92c3cad3ba6b41e1296ef681692372886db86"},"mac":"01816d0a5c31cd03b644f2d756ac8167c2498808040cbace8c35c46dcf06b7a1","cipher":"aes-128-ctr"},"address":"32dd55E0BCF509a35A3F5eEb8593fbEb244796b1"}',
    "Derivation path: m/44'/0'/0'/0/0",
    "333f226d7631860d3020432d497b4333a74edbb4709e3fdf75be0e0bea34475a",
    "23d74c7c36b814a23ea337739da22de5",
    "fb67a6394c139ae6a87ff257804157c7f5414ce9",
    "02916003240a8e59b0ac4ff4ae1fbda1eb720323484439f49af98827d4388e1cf0",
    "04a489a5b3785d951606b9e6a6fb90819201bebfef06e9becd629ed38e207cb1a9ddff7d50034bd1849a3554d60dc19dd2d36e190d1d56be003d89a7439655a0d9"
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
