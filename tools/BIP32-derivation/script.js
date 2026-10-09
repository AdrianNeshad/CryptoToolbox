// BIP32 Derivation Preview
// Decodes an extended key locally and derives Legacy / Nested SegWit / Native
// SegWit addresses for a given path. Pure client-side; no network access.
// Reuses the vendored bitcoinjs-lib 3.3.0 bundle and bech32 helper shipped
// with the BIP38 Key Compression tool.

(function () {
    "use strict";

    var B = window.bitcoinjs;
    var encodeSegwitAddress = window.encodeSegwitAddress;

    var keyInput = document.getElementById("key-input");
    var pathInput = document.getElementById("path-input");
    var countInput = document.getElementById("count-input");
    var keyMeta = document.getElementById("key-meta");
    var deriveBtn = document.getElementById("derive-btn");
    var sampleBtn = document.getElementById("sample-btn");
    var clearBtn = document.getElementById("clear-btn");
    var copyAllBtn = document.getElementById("copy-all-btn");
    var errorPanel = document.getElementById("error-panel");
    var errorBody = document.getElementById("error-body");
    var outputWrap = document.getElementById("output-wrap");
    var outputSummary = document.getElementById("output-summary");
    var addrBody = document.getElementById("addr-body");
    var toast = document.getElementById("toast");

    if (!B || !B.bitcoin || !encodeSegwitAddress) {
        showError("Could not load the local crypto library. Make sure the tool is opened from within CryptoToolbox.");
        deriveBtn.disabled = true;
        return;
    }

    var bitcoin = B.bitcoin;
    var Buffer = B.Buffer.Buffer;
    var bs58check = B.bs58check;
    var NETWORKS = bitcoin.networks;

    // BIP44 account 0 xpub for the canonical "abandon … about" test mnemonic
    // (m/44'/0'/0'). m/0/0 legacy address = 1LqBGSKuTcfaewBksWrbA8xdJvC6SjuEfS.
    var SAMPLE_XPUB =
        "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";

    // Extended-key version prefixes → how to read them.
    var EXT_VERSIONS = {
        0x0488b21e: { kind: "public", fmt: "legacy", net: "main", sym: "xpub" },
        0x049d7cb2: { kind: "public", fmt: "p2sh", net: "main", sym: "ypub" },
        0x04b24746: { kind: "public", fmt: "bech32", net: "main", sym: "zpub" },
        0x0488ade4: { kind: "private", fmt: "legacy", net: "main", sym: "xprv" },
        0x049d7878: { kind: "private", fmt: "p2sh", net: "main", sym: "yprv" },
        0x04b2430c: { kind: "private", fmt: "bech32", net: "main", sym: "zprv" },
        0x043587cf: { kind: "public", fmt: "legacy", net: "test", sym: "tpub" },
        0x044a5262: { kind: "public", fmt: "p2sh", net: "test", sym: "upub" },
        0x045f1cf6: { kind: "public", fmt: "bech32", net: "test", sym: "vpub" },
        0x04358394: { kind: "private", fmt: "legacy", net: "test", sym: "tprv" },
        0x044a4e28: { kind: "private", fmt: "p2sh", net: "test", sym: "uprv" },
        0x045f18bc: { kind: "private", fmt: "bech32", net: "test", sym: "vprv" }
    };

    var FMT_LABEL = { legacy: "Legacy", p2sh: "Nested SegWit", bech32: "Native SegWit" };

    // ---------- Loading / normalising an extended key ----------

    function loadKey(str) {
        var buf;
        try {
            buf = bs58check.decode(str.trim());
        } catch (e) {
            throw new Error("Not valid Base58Check — this does not look like an extended key.");
        }
        if (buf.length !== 78) {
            throw new Error("Wrong length for an extended key (expected 78 bytes, got " + buf.length + ").");
        }
        var ver = buf.readUInt32BE(0);
        var meta = EXT_VERSIONS[ver];
        if (!meta) {
            throw new Error("Unrecognised extended-key version prefix (0x" + ver.toString(16) + ").");
        }
        var net = meta.net === "test" ? NETWORKS.testnet : NETWORKS.bitcoin;
        // bitcoinjs 3.3.0 only knows the standard xpub/xprv (and tpub/tprv)
        // version bytes, so re-stamp ypub/zpub/etc. to their plain BIP32
        // equivalent. The underlying key material is identical; only the
        // suggested default address format differs.
        var normVer = meta.net === "test"
            ? (meta.kind === "public" ? 0x043587cf : 0x04358394)
            : (meta.kind === "public" ? 0x0488b21e : 0x0488ade4);
        var nbuf = Buffer.from(buf);
        nbuf.writeUInt32BE(normVer, 0);

        var node;
        var metaFixed = false;
        try {
            node = bitcoin.HDNode.fromBase58(bs58check.encode(nbuf), net);
        } catch (e) {
            // Some exported (and dummy/test) keys carry inconsistent header
            // metadata — most commonly a depth-0 "master" key whose parent
            // fingerprint or child-index fields are non-zero. Those fields are
            // not used when deriving child keys (derivation uses only the chain
            // code and public key), so zero them and retry instead of refusing.
            if (/parent fingerprint|Invalid index/i.test(e.message)) {
                nbuf.fill(0, 5, 13); // parent fingerprint (bytes 5-8) + child index (9-12)
                try {
                    node = bitcoin.HDNode.fromBase58(bs58check.encode(nbuf), net);
                    metaFixed = true;
                } catch (e2) {
                    throw new Error(humanizeKeyError(e2.message));
                }
            } else {
                throw new Error(humanizeKeyError(e.message));
            }
        }
        return { node: node, meta: meta, net: net, depth: buf[4], metaFixed: metaFixed };
    }

    function humanizeKeyError(msg) {
        if (/not on the curve|Invalid point|invalid sequence|Expected property/i.test(msg)) {
            return "This key's embedded public key is not a valid point on the secp256k1 curve, so it isn't a " +
                "real extended key — it looks like a dummy, placeholder or corrupted value, not a derivable xpub.";
        }
        if (/Invalid private key/i.test(msg)) {
            return "The private-key bytes in this extended key are invalid — the value looks corrupted.";
        }
        return "Could not parse the key: " + msg;
    }

    // ---------- Path parsing ----------
    // Returns an array of { index, hardened }. For a public key the leading
    // hardened account prefix (e.g. 44'/0'/0') is stripped, because an xpub
    // can only derive non-hardened children.

    function parsePath(input, isPublic) {
        var s = String(input || "").trim().replace(/^m\//i, "").replace(/^\//, "");
        if (s === "" || s.toLowerCase() === "m") return { levels: [], stripped: 0 };
        var parts = s.split("/").filter(function (p) { return p.length > 0; });
        var levels = parts.map(function (p) {
            var hardened = /['hH]$/.test(p);
            var raw = p.replace(/['hH]$/, "");
            if (!/^\d+$/.test(raw)) throw new Error('Invalid path component: "' + p + '".');
            var num = parseInt(raw, 10);
            if (num > 0x7fffffff) throw new Error('Index out of range: "' + p + '".');
            return { index: num, hardened: hardened };
        });

        if (isPublic) {
            var firstNonH = -1;
            for (var i = 0; i < levels.length; i++) {
                if (!levels[i].hardened) { firstNonH = i; break; }
            }
            if (firstNonH === -1) {
                throw new Error("This path is entirely hardened. An extended public key can only derive " +
                    "non-hardened children — provide a path like 0/0, or paste the extended private key.");
            }
            var tail = levels.slice(firstNonH);
            if (tail.some(function (l) { return l.hardened; })) {
                throw new Error("Hardened levels (with ') can't be derived from a public key. Use a non-hardened " +
                    "path like 0/0, or paste the extended private key.");
            }
            return { levels: tail, stripped: firstNonH };
        }
        return { levels: levels, stripped: 0 };
    }

    function deriveNode(root, levels) {
        var n = root;
        for (var i = 0; i < levels.length; i++) {
            n = levels[i].hardened ? n.deriveHardened(levels[i].index) : n.derive(levels[i].index);
        }
        return n;
    }

    // ---------- Address encoders ----------

    function addrLegacy(node) {
        return node.getAddress();
    }

    function addrNested(node, net) {
        var h160 = bitcoin.crypto.hash160(node.getPublicKeyBuffer());
        var redeem = Buffer.concat([Buffer.from([0x00, 0x14]), h160]);
        return bitcoin.address.toBase58Check(bitcoin.crypto.hash160(redeem), net.scriptHash);
    }

    function addrNative(node, net) {
        var h160 = bitcoin.crypto.hash160(node.getPublicKeyBuffer());
        return encodeSegwitAddress(net.bech32, 0, h160);
    }

    // ---------- Rendering ----------

    function pathLabel(levels) {
        if (!levels.length) return "m";
        return "m/" + levels.map(function (l) {
            return l.index + (l.hardened ? "'" : "");
        }).join("/");
    }

    function showError(msg) {
        errorBody.textContent = msg;
        errorPanel.classList.remove("display-none");
        outputWrap.classList.add("display-none");
    }

    function hideError() {
        errorPanel.classList.add("display-none");
    }

    function showToast(text) {
        toast.textContent = text;
        toast.classList.add("show");
        setTimeout(function () { toast.classList.remove("show"); }, 1800);
    }

    function copyText(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () { showToast("Copied"); },
                function () { fallbackCopy(text); });
        } else {
            fallbackCopy(text);
        }
    }

    function fallbackCopy(text) {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); showToast("Copied"); } catch (e) { /* ignore */ }
        ta.remove();
    }

    var lastRows = [];
    var currentDefaultFmt = "legacy";

    function run() {
        hideError();
        keyMeta.classList.add("display-none");
        var raw = keyInput.value.trim();
        if (!raw) {
            showError("Paste an extended key first.");
            return;
        }

        var loaded;
        try {
            loaded = loadKey(raw);
        } catch (e) {
            showError(e.message);
            return;
        }

        var isPublic = loaded.meta.kind === "public";
        var parsed;
        try {
            parsed = parsePath(pathInput.value, isPublic);
        } catch (e) {
            showError(e.message);
            return;
        }

        // Key metadata banner
        var netLabel = loaded.meta.net === "test" ? "testnet" : "mainnet";
        var metaHtml = "<strong>" + loaded.meta.sym + "</strong> · " +
            (isPublic ? "public" : "private") + " · " + netLabel +
            " · default format: " + FMT_LABEL[loaded.meta.fmt] +
            " · depth " + loaded.depth;
        if (loaded.metaFixed) {
            metaHtml += '<div class="key-note key-note--warn">Heads up: this key\'s header metadata is ' +
                "inconsistent (a depth-0 master key with a non-zero parent fingerprint / index) — often a " +
                "dummy or test key. Addresses are still derived, since those fields don't affect derivation, " +
                "but double-check that this is a real wallet key.</div>";
        }
        if (parsed.stripped > 0) {
            metaHtml += '<div class="key-note">Ignored the first ' + parsed.stripped +
                " hardened level" + (parsed.stripped === 1 ? "" : "s") +
                " of the path — those are baked into the extended key already.</div>";
        }
        keyMeta.innerHTML = metaHtml;
        keyMeta.classList.remove("display-none");

        var levels = parsed.levels;
        var count = Math.max(1, Math.min(100, parseInt(countInput.value, 10) || 1));

        // Vary the last path component across `count` addresses. With an empty
        // path (the key itself) there is nothing to vary, so show a single row.
        var startIndex = levels.length ? levels[levels.length - 1].index : 0;
        var varies = levels.length > 0;

        var rows = [];
        try {
            for (var k = 0; k < count; k++) {
                var theseLevels = levels.map(function (l) { return { index: l.index, hardened: l.hardened }; });
                if (varies) theseLevels[theseLevels.length - 1].index = startIndex + k;
                var node = deriveNode(loaded.node, theseLevels);
                rows.push({
                    path: pathLabel(theseLevels),
                    legacy: addrLegacy(node),
                    nested: addrNested(node, loaded.net),
                    native: addrNative(node, loaded.net)
                });
                if (!varies) break;
            }
        } catch (e) {
            showError("Derivation failed: " + e.message);
            return;
        }

        lastRows = rows;
        currentDefaultFmt = loaded.meta.fmt;
        renderRows(rows);
        outputSummary.textContent = rows.length + (rows.length === 1 ? " address" : " addresses") +
            " · " + FMT_LABEL[loaded.meta.fmt] + " is this key's default";
        outputWrap.classList.remove("display-none");
    }

    function cell(addr, isDefault) {
        var td = document.createElement("td");
        td.className = "addr-cell" + (isDefault ? " addr-cell--default" : "");
        var code = document.createElement("code");
        code.textContent = addr;
        td.appendChild(code);
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "mini-copy";
        btn.textContent = "Copy";
        btn.addEventListener("click", function () { copyText(addr); });
        td.appendChild(btn);
        return td;
    }

    function renderRows(rows) {
        addrBody.innerHTML = "";
        var defaultFmt = currentDefaultFmt;
        rows.forEach(function (r) {
            var tr = document.createElement("tr");
            var pth = document.createElement("td");
            pth.className = "path-cell";
            pth.textContent = r.path;
            tr.appendChild(pth);
            tr.appendChild(cell(r.legacy, defaultFmt === "legacy"));
            tr.appendChild(cell(r.nested, defaultFmt === "p2sh"));
            tr.appendChild(cell(r.native, defaultFmt === "bech32"));
            addrBody.appendChild(tr);
        });
    }

    // ---------- Events ----------

    deriveBtn.addEventListener("click", run);

    // Preset derivation-path buttons: fill the path and derive if a key is
    // already present, otherwise just set the path and focus the key field.
    var presetRow = document.getElementById("preset-row");
    if (presetRow) {
        presetRow.addEventListener("click", function (e) {
            var btn = e.target.closest(".preset-btn");
            if (!btn) return;
            pathInput.value = btn.getAttribute("data-path");
            if (keyInput.value.trim()) {
                run();
            } else {
                keyInput.focus();
            }
        });
    }

    pathInput.addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
    countInput.addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });

    sampleBtn.addEventListener("click", function () {
        keyInput.value = SAMPLE_XPUB;
        pathInput.value = "m/0/0";
        countInput.value = "5";
        run();
    });

    clearBtn.addEventListener("click", function () {
        keyInput.value = "";
        pathInput.value = "m/0/0";
        countInput.value = "5";
        keyMeta.classList.add("display-none");
        outputWrap.classList.add("display-none");
        hideError();
        keyInput.focus();
    });

    copyAllBtn.addEventListener("click", function () {
        if (!lastRows.length) return;
        var lines = lastRows.map(function (r) {
            return r.path + "\t" + r.legacy + "\t" + r.nested + "\t" + r.native;
        });
        copyText(lines.join("\n"));
    });

    // ---------- Theme sync with the CryptoToolbox shell ----------

    window.addEventListener("message", function (event) {
        if (event.source !== window.parent) return;
        var data = event.data;
        if (!data || data.source !== "cryptotoolbox") return;

        if (data.type === "theme" && (data.theme === "light" || data.theme === "dark")) {
            document.documentElement.setAttribute("data-theme", data.theme);
            try { localStorage.setItem("theme", data.theme); } catch (e) { /* ignored */ }
        }
    });

    keyInput.focus();
})();
