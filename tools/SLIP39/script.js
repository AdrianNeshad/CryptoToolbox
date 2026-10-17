// SLIP-39 Shamir Backup — UI
// Create, recover, inspect/repair and extend SLIP-39 share sets. All crypto is
// in lib/slip39.js (validated against the official SLIP-0039 vectors); this
// file only wires it to the page. Pure client-side; no network access.

(function () {
    "use strict";

    var S = window.SLIP39;
    var B39 = window.BIP39Lite;
    var BJ = window.bitcoinjs;
    var hex = S && S.bytesToHex;

    function $(id) { return document.getElementById(id); }

    function esc(s) {
        return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
        });
    }

    function fmt(n) { return Number(n).toLocaleString("en-US"); }

    function plural(n, one, many) { return n + " " + (n === 1 ? one : (many || one + "s")); }

    function debounce(fn, ms) {
        var t;
        return function () { clearTimeout(t); t = setTimeout(fn, ms); };
    }

    if (!S || !window.SLIP39_WORDLIST) {
        document.getElementById("container").insertAdjacentHTML("beforeend",
            '<div class="result-panel"><div class="result-title">Could not load the SLIP-39 library</div>' +
            '<div class="result-body">Open this tool from within CryptoToolbox so its lib/ scripts load.</div></div>');
        return;
    }

    // ---------- Toast & clipboard ----------

    var toast = $("toast");
    var toastTimer;
    function showToast(text) {
        toast.textContent = text;
        toast.classList.add("show");
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { toast.classList.remove("show"); }, 1800);
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

    // Copy buttons carry an index into this list instead of the value itself.
    var copyStore = [];
    function copyBtn(text, label) {
        var i = copyStore.push(text) - 1;
        return '<button type="button" class="mini-btn" data-copy="' + i + '">' + esc(label || "Copy") + "</button>";
    }

    // Generic action buttons: data-act="<id>" → handler from this map
    var actStore = [];
    function actBtn(label, fn, cls) {
        var i = actStore.push(fn) - 1;
        return '<button type="button" class="' + (cls || "mini-btn") + '" data-act="' + i + '">' + esc(label) + "</button>";
    }

    document.addEventListener("click", function (e) {
        var c = e.target.closest("[data-copy]");
        if (c) { copyText(copyStore[+c.getAttribute("data-copy")]); return; }
        var a = e.target.closest("[data-act]");
        if (a) { actStore[+a.getAttribute("data-act")](a); }
    });

    // ---------- Small UI helpers ----------

    function showError(id, msg) {
        var p = $(id);
        p.querySelector(".result-body").textContent = msg;
        p.classList.remove("display-none");
    }
    function hideError(id) { $(id).classList.add("display-none"); }

    function setBusy(id, text) {
        var el = $(id);
        el.textContent = text || "";
        el.classList.toggle("is-busy", !!text);
    }

    function setPills(row, attr, value) {
        row.querySelectorAll(".pill").forEach(function (b) {
            b.setAttribute("aria-pressed", String(b.getAttribute(attr) === value));
        });
    }

    function pillValue(row, attr) {
        var b = row.querySelector('.pill[aria-pressed="true"]');
        return b ? b.getAttribute(attr) : null;
    }

    function fillExponentSelect(sel, selected) {
        var html = "";
        for (var e = 0; e <= 15; e++) {
            html += '<option value="' + e + '"' + (e === selected ? " selected" : "") + ">" + e + " — " +
                fmt(10000 * Math.pow(2, e)) + " iterations" + (e === 1 ? " (default)" : "") +
                (e >= 8 ? " · slow" : "") + "</option>";
        }
        sel.innerHTML = html;
    }

    document.querySelectorAll(".pw-toggle").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var ids = btn.getAttribute("data-target").split(" ");
            var show = $(ids[0]).type === "password";
            ids.forEach(function (id) { $(id).type = show ? "text" : "password"; });
            btn.textContent = show ? "Hide" : "Show";
        });
    });

    function describeExp(e) {
        return "iteration exponent " + e + " (" + fmt(10000 * Math.pow(2, e)) + " PBKDF2 iterations)";
    }

    function wordGrid(words, classFor) {
        return '<div class="word-grid">' + words.map(function (w, i) {
            var cls = classFor ? classFor(i) : "";
            return '<span class="w ' + cls + '"><span class="n">' + (i + 1) + "</span>" + esc(w == null ? "?" : w) + "</span>";
        }).join("") + "</div>";
    }

    // ---------- Tabs ----------

    var tabs = $("tabs");
    function selectTab(name) {
        tabs.querySelectorAll(".tab").forEach(function (t) {
            t.setAttribute("aria-selected", String(t.getAttribute("data-tab") === name));
        });
        document.querySelectorAll(".tab-panel").forEach(function (p) {
            p.classList.toggle("display-none", p.id !== "tab-" + name);
        });
        try { sessionStorage.setItem("slip39-tab", name); } catch (e) { /* ignored */ }
    }
    tabs.addEventListener("click", function (e) {
        var t = e.target.closest(".tab");
        if (t) selectTab(t.getAttribute("data-tab"));
    });
    try {
        var savedTab = sessionStorage.getItem("slip39-tab");
        if (savedTab && $("tab-" + savedTab)) selectTab(savedTab);
    } catch (e) { /* ignored */ }

    // ---------- Scheme editor (used by Create and Extend) ----------

    var PRESETS = [
        { id: "single", label: "Single share", sub: "1 of 1", gt: 1, groups: [[1, 1]] },
        { id: "2of3", label: "2 of 3", gt: 1, groups: [[2, 3]] },
        { id: "3of5", label: "3 of 5", gt: 1, groups: [[3, 5]] },
        { id: "master", label: "Master + 3 of 5", gt: 1, groups: [[1, 1], [3, 5]] },
        { id: "groups", label: "2 of 3 groups", gt: 2, groups: [[1, 1], [2, 3], [3, 5]] }
    ];

    function SchemeEditor(root, presetId) {
        var preset = PRESETS.filter(function (p) { return p.id === presetId; })[0] || PRESETS[1];
        var state = { gt: preset.gt, groups: preset.groups.map(function (g) { return g.slice(); }) };

        root.innerHTML =
            '<div class="pill-row preset-row">' +
            '<span class="pill-label">Presets</span>' +
            PRESETS.map(function (p) {
                return '<button type="button" class="pill" data-preset="' + p.id + '">' + esc(p.label) +
                    (p.sub ? " <code>" + esc(p.sub) + "</code>" : "") + "</button>";
            }).join("") +
            "</div>" +
            '<div class="scheme-top">Recovery needs <input type="number" class="gt-input" min="1" max="16"> of ' +
            '<span class="gcount"></span> groups</div>' +
            '<div class="scheme-groups"></div>' +
            '<div class="action-row" style="margin-bottom:0"><button type="button" class="secondary add-group">+ Add group</button></div>' +
            '<div class="scheme-summary"></div>';

        var presetRow = root.querySelector(".preset-row");
        var gtInput = root.querySelector(".gt-input");
        var top = root.querySelector(".scheme-top");
        var list = root.querySelector(".scheme-groups");
        var summary = root.querySelector(".scheme-summary");
        var addBtn = root.querySelector(".add-group");

        function groupProblem(g) {
            var t = g[0], n = g[1];
            if (!(n >= 1 && n <= 16)) return "The number of shares must be 1 – 16.";
            if (!(t >= 1 && t <= n)) return "The threshold must be 1 – " + n + ".";
            if (t === 1 && n > 1) return "1-of-" + n + " isn't allowed by SLIP-39 (every share would be the same secret). Use 1 of 1 and copy that share.";
            return null;
        }

        function problem() {
            var bad = null;
            state.groups.forEach(function (g, i) { var p = groupProblem(g); if (p && !bad) bad = "Group " + (i + 1) + ": " + p; });
            if (bad) return bad;
            if (!(state.gt >= 1 && state.gt <= state.groups.length)) return "The group threshold must be 1 – " + state.groups.length + ".";
            return null;
        }

        function renderRows() {
            var multi = state.groups.length > 1;
            top.classList.toggle("display-none", !multi);
            list.innerHTML = state.groups.map(function (g, i) {
                return '<div class="scheme-group" data-i="' + i + '">' +
                    '<span class="scheme-group-name">' + (multi ? "Group " + (i + 1) : "Shares") + "</span>" +
                    '<input type="number" class="t-input" min="1" max="16" value="' + g[0] + '"> of ' +
                    '<input type="number" class="n-input" min="1" max="16" value="' + g[1] + '"> shares needed' +
                    '<span class="scheme-group-msg"></span>' +
                    (multi ? '<button type="button" class="icon-btn rm-group" title="Remove group" aria-label="Remove group">&times;</button>' : "") +
                    "</div>";
            }).join("");
            addBtn.disabled = state.groups.length >= 16;
            refresh();
        }

        function refresh() {
            gtInput.value = state.gt;
            gtInput.max = state.groups.length;
            root.querySelector(".gcount").textContent = state.groups.length;
            list.querySelectorAll(".scheme-group").forEach(function (row) {
                var g = state.groups[+row.getAttribute("data-i")];
                var p = groupProblem(g);
                row.classList.toggle("is-invalid", !!p);
                row.querySelector(".scheme-group-msg").textContent = p || "";
            });
            var p = problem();
            summary.classList.toggle("is-error", !!p);
            if (p) {
                summary.textContent = p;
            } else {
                var total = state.groups.reduce(function (a, g) { return a + g[1]; }, 0);
                if (state.groups.length === 1) {
                    var g = state.groups[0];
                    summary.textContent = g[1] === 1 ? "One share holds the whole secret — this is a plain single backup." :
                        "Any " + g[0] + " of the " + g[1] + " shares recover the secret; " + (g[0] - 1) + " or fewer reveal nothing.";
                } else {
                    summary.textContent = "Recovery needs " + state.gt + " of " + state.groups.length + " groups, each with its own threshold. " +
                        plural(total, "share") + " in total.";
                }
            }
            presetRow.querySelectorAll(".pill").forEach(function (b) {
                var pr = PRESETS.filter(function (x) { return x.id === b.getAttribute("data-preset"); })[0];
                b.setAttribute("aria-pressed", String(pr.gt === state.gt && JSON.stringify(pr.groups) === JSON.stringify(state.groups)));
            });
        }

        presetRow.addEventListener("click", function (e) {
            var b = e.target.closest(".pill");
            if (!b) return;
            var pr = PRESETS.filter(function (x) { return x.id === b.getAttribute("data-preset"); })[0];
            state.gt = pr.gt;
            state.groups = pr.groups.map(function (g) { return g.slice(); });
            renderRows();
        });
        gtInput.addEventListener("input", function () { state.gt = parseInt(gtInput.value, 10) || 0; refresh(); });
        list.addEventListener("input", function (e) {
            var row = e.target.closest(".scheme-group");
            if (!row) return;
            var g = state.groups[+row.getAttribute("data-i")];
            if (e.target.classList.contains("t-input")) g[0] = parseInt(e.target.value, 10) || 0;
            if (e.target.classList.contains("n-input")) g[1] = parseInt(e.target.value, 10) || 0;
            refresh();
        });
        list.addEventListener("click", function (e) {
            var rm = e.target.closest(".rm-group");
            if (!rm) return;
            state.groups.splice(+rm.closest(".scheme-group").getAttribute("data-i"), 1);
            state.gt = Math.min(state.gt, state.groups.length);
            if (state.groups.length === 1) state.gt = 1;
            renderRows();
        });
        addBtn.addEventListener("click", function () {
            if (state.groups.length >= 16) return;
            state.groups.push([2, 3]);
            renderRows();
        });

        renderRows();

        return {
            get: function () {
                var p = problem();
                if (p) throw new Error(p);
                return { groupThreshold: state.groups.length === 1 ? 1 : state.gt, groups: state.groups.map(function (g) { return g.slice(); }) };
            }
        };
    }

    // ---------- Parsing pasted share text ----------

    // Returns [{ text, line }]: one entry per share. Lines starting with # or //
    // are comments. A block of consecutive lines is one share unless each
    // line is a share on its own.
    function splitShareText(text) {
        var lines = String(text || "").split(/\r?\n/);
        var blocks = [], cur = [];
        lines.forEach(function (line, i) {
            var t = line.trim();
            if (/^(#|\/\/)/.test(t)) t = "";
            if (!t) { if (cur.length) { blocks.push(cur); cur = []; } return; }
            cur.push({ text: t, line: i + 1 });
        });
        if (cur.length) blocks.push(cur);

        var out = [];
        blocks.forEach(function (b) {
            if (b.length === 1) { out.push(b[0]); return; }
            var each = b.every(function (l) { return S.tokenize(l.text).length >= S.MIN_MNEMONIC_LENGTH_WORDS; });
            var joined = { text: b.map(function (l) { return l.text; }).join(" "), line: b[0].line, lineEnd: b[b.length - 1].line };
            if (!each) { out.push(joined); return; }
            // Every line is long enough to be a share. Prefer that reading, unless
            // the lines are invalid on their own but valid when joined.
            var eachValid = b.every(function (l) { return decodeEntry(l.text).ok; });
            if (!eachValid && decodeEntry(joined.text).ok) out.push(joined);
            else b.forEach(function (l) { out.push(l); });
        });
        return out;
    }

    function decodeEntry(text) {
        var resolved = S.resolveWords(text);
        var res = { text: text, resolved: resolved, ok: false };
        res.expanded = resolved.filter(function (r) { return r.status === "prefix" || r.status === "fuzzy"; });
        var unknown = resolved.filter(function (r) { return r.index === null; });
        if (!resolved.length) { res.error = "Empty."; return res; }
        if (unknown.length) {
            var u = unknown[0];
            res.error = u.status === "placeholder"
                ? plural(unknown.length, "word is", "words are") + " marked as unknown (?)."
                : "\"" + u.token + "\" is not a SLIP-39 word" + (u.suggestions ? " (closest: " + u.suggestions.slice(0, 3).join(", ") + ")" : "") +
                  (unknown.length > 1 ? ", and " + plural(unknown.length - 1, "more unknown word") : "") + ".";
            res.repairable = true;
            return res;
        }
        try {
            res.share = S.decodeShare(resolved.map(function (r) { return r.index; }));
            res.ok = true;
        } catch (e) {
            res.error = e.message;
            res.repairable = e.code === "checksum" || e.code === "padlen" || e.code === "length" || e.code === "padding";
        }
        return res;
    }

    function groupPrefix(share, groupIndex) {
        var s = {
            identifier: share.identifier, extendable: share.extendable, iterationExponent: share.iterationExponent,
            groupIndex: groupIndex, groupThreshold: share.groupThreshold, groupCount: share.groupCount,
            memberIndex: 0, memberThreshold: 1, value: share.value
        };
        return S.encodeShare(s).slice(0, S.GROUP_PREFIX_LENGTH_WORDS).join(" ");
    }

    // Parses a share textarea and classifies everything into one share set.
    function parseShareSet(text) {
        var entries = splitShareText(text).map(function (e) {
            var d = decodeEntry(e.text);
            d.line = e.line;
            d.lineEnd = e.lineEnd;
            return d;
        });
        var valid = [], map = [];
        entries.forEach(function (e, i) { if (e.ok) { map.push(i); valid.push(e.share); } });
        var analysis = S.analyzeShares(valid);
        analysis.mismatched.forEach(function (m) { entries[map[m.idx]].warn = "Not part of this set — " + m.reason + "."; entries[map[m.idx]].ignored = true; });
        analysis.duplicates.forEach(function (m) { entries[map[m.idx]].warn = "Duplicate share — ignored."; entries[map[m.idx]].ignored = true; });
        analysis.conflicts.forEach(function (m) {
            entries[map[m.idx]].bad = "Same group and member index as " + lineLabel(entries[map[m.other]]).toLowerCase() +
                ", but different words — one of the two is wrong, or they come from different share sets with the same identifier.";
            entries[map[m.idx]].ignored = true;
        });
        analysis.groups.forEach(function (g) {
            g.thresholdConflicts.forEach(function (m) {
                entries[map[m.idx]].bad = "Its member threshold differs from the other shares of group " + (g.groupIndex + 1) + ".";
                entries[map[m.idx]].ignored = true;
            });
            g.members.forEach(function (m) { m.entry = entries[map[m.idx]]; });
        });
        return { entries: entries, analysis: analysis, valid: valid };
    }

    function lineLabel(e) {
        return e.lineEnd ? "Lines " + e.line + "–" + e.lineEnd : "Line " + e.line;
    }

    // Renders the per-share list and the set progress.
    function renderSetStatus(container, set, opts) {
        opts = opts || {};
        var a = set.analysis;
        var html = "";
        if (a.params) {
            var p = a.params;
            var ref = set.valid[0];
            var gpRows = "";
            for (var gi = 0; gi < p.groupCount; gi++) {
                var g = a.groups.get(gi);
                var have = g ? g.members.length : 0;
                var cls = g && g.complete ? "gp-done" : have ? "gp-part" : "gp-none";
                var icon = g && g.complete ? "✓" : have ? "●" : "○";
                var label = g
                    ? have + " of " + g.memberThreshold + " shares" + (g.complete && have > g.memberThreshold ? " (+" + (have - g.memberThreshold) + " extra)" : "")
                    : "no shares yet";
                gpRows += '<div class="gp-row ' + cls + '"><span class="gp-icon">' + icon + "</span>" +
                    "<span>" + (p.groupCount > 1 ? "Group " + (gi + 1) + " — " : "") + esc(label) + "</span>" +
                    '<span class="gp-prefix">' + esc(groupPrefix(ref, gi)) + " …</span></div>";
            }
            var need = p.groupCount > 1
                ? "Needs " + p.groupThreshold + " of " + p.groupCount + " groups · " + a.completeGroups + " complete"
                : "Needs " + (a.groups.get(0) ? a.groups.get(0).memberThreshold : "?") + " share(s) of the single group";
            html += '<div class="set-summary">' +
                '<div class="set-title">' + (a.complete ? '<span class="badge badge--ok">Ready</span> ' : '<span class="badge">Incomplete</span> ') +
                esc(need) + "</div>" +
                '<div class="set-meta">Identifier ' + p.identifier + " · " + (p.extendable ? "extendable" : "non-extendable") + " · " +
                esc(describeExp(p.iterationExponent)) + " · " + (p.valueBytes * 8) + "-bit secret</div>" +
                '<div class="group-progress">' + gpRows + "</div></div>";
        }

        html += '<div class="share-list">' + set.entries.map(function (e) {
            var cls, icon, label, notes = "";
            if (!e.ok) { cls = "is-bad"; icon = "✗"; label = "Invalid share"; }
            else if (e.bad) { cls = "is-bad"; icon = "✗"; }
            else if (e.warn) { cls = "is-warn"; icon = "!"; }
            else { cls = "is-ok"; icon = "✓"; }
            if (e.ok) {
                var s = e.share;
                label = (s.groupCount > 1 ? "Group " + (s.groupIndex + 1) + " · " : "") + "Share #" + (s.memberIndex + 1) +
                    ' <span class="card-sub">(' + s.memberThreshold + " needed" + (s.groupCount > 1 ? " in this group" : "") + ")</span>";
            }
            var words = e.resolved.map(function (r) { return r.word || r.token; });
            if (!e.ok) notes += '<div class="sr-note sr-note--bad">' + esc(e.error) + "</div>";
            if (e.bad) notes += '<div class="sr-note sr-note--bad">' + esc(e.bad) + "</div>";
            if (e.warn) notes += '<div class="sr-note sr-note--warn">' + esc(e.warn) + "</div>";
            var fuzzy = e.expanded.filter(function (r) { return r.status === "fuzzy"; });
            if (fuzzy.length) {
                notes += '<div class="sr-note sr-note--warn">Read by their first four letters: ' +
                    fuzzy.map(function (r) { return "“" + esc(r.token) + "” → " + esc(r.word); }).join(", ") + "</div>";
            }
            if (e.inconsistent) notes += '<div class="sr-note sr-note--bad">' + esc(e.inconsistent) + "</div>";
            var actions = "";
            if (!e.ok && e.repairable) {
                actions = '<div class="sr-actions">' + actBtn("Repair in Inspect tab", function () { openInInspect(e.text); }) + "</div>";
            }
            return '<div class="share-row ' + cls + '"><span class="sr-icon">' + icon + "</span>" +
                '<div class="sr-main"><div><span class="sr-label">' + label + "</span> " +
                '<span class="card-sub">· ' + esc(lineLabel(e)) + " · " + words.length + " words</span></div>" +
                '<div class="sr-words">' + esc(words.slice(0, 4).join(" ")) + (words.length > 4 ? " …" : "") + "</div>" +
                notes + actions + "</div></div>";
        }).join("") + "</div>";

        container.innerHTML = set.entries.length ? html : "";
    }

    function openInInspect(text) {
        $("inspect-input").value = text;
        selectTab("inspect");
        runInspect();
        $("inspect-input").focus();
    }

    // ---------- Share-set output (Create / Extend) ----------

    function setToText(groups, meta) {
        var lines = [
            "# SLIP-39 share set",
            "# Identifier " + meta.identifier + " · " + (meta.extendable ? "extendable" : "non-extendable") + " · " + describeExp(meta.iterationExponent),
            "# Recovery needs " + (groups.length > 1 ? meta.groupThreshold + " of " + groups.length + " groups" : groups[0][0].memberThreshold + " of " + groups[0].length + " shares")
        ];
        groups.forEach(function (g, gi) {
            lines.push("#");
            if (groups.length > 1) lines.push("# Group " + (gi + 1) + " of " + groups.length + " — " + g[0].memberThreshold + " of " + g.length + " shares needed");
            g.forEach(function (s) { lines.push(s.mnemonic); });
        });
        return lines.join("\n") + "\n";
    }

    function saveText(text, name) {
        var url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
        var a = document.createElement("a");
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    function printElement(el) {
        document.body.classList.add("print-mode");
        el.classList.add("print-target");
        var done = function () {
            document.body.classList.remove("print-mode");
            el.classList.remove("print-target");
            window.removeEventListener("afterprint", done);
        };
        window.addEventListener("afterprint", done);
        window.print();
        setTimeout(done, 1000);
    }

    function shareCardHtml(s, title, sub, classFor) {
        return '<div class="share-card">' +
            '<div class="share-card-head"><div class="share-card-title">' + esc(title) +
            (sub ? '<span class="card-sub">' + esc(sub) + "</span>" : "") + "</div>" +
            copyBtn(s.mnemonic) + "</div>" +
            wordGrid(s.words, classFor) + "</div>";
    }

    function groupCardsHtml(groups, opts) {
        opts = opts || {};
        return groups.map(function (g, gi) {
            var t = g[0].memberThreshold;
            var gIndex = g[0].groupIndex;
            var head = groups.length > 1 || opts.forceGroupTitle
                ? "Group " + (gIndex + 1) + (g[0].groupCount > 1 ? " of " + g[0].groupCount : "")
                : "Shares";
            var sub = t === 1 && g.length === 1 ? "this share alone recovers " + (g[0].groupCount > 1 ? "the group" : "the secret")
                : t + " of " + g.length + " shares needed";
            return '<div class="card group-card"><div class="card-head"><span>' + esc(head) +
                ' <span class="card-sub">— ' + esc(sub) + "</span></span>" +
                '<div class="card-actions">' + copyBtn(g.map(function (s) { return s.mnemonic; }).join("\n"), "Copy group") + "</div></div>" +
                '<div class="share-cards">' + g.map(function (s) {
                    return shareCardHtml(s, "Share #" + (s.memberIndex + 1), groups.length > 1 || opts.forceGroupTitle ? "group " + (gIndex + 1) : "");
                }).join("") + "</div></div>";
        }).join("");
    }

    function renderShareSet(container, groups, meta, kvRows, banner) {
        var text = setToText(groups, meta);
        var actions = '<div class="card-actions">' + copyBtn(text, "Copy all") +
            actBtn("Save .txt", function () { saveText(text, "slip39-shares-" + meta.identifier + ".txt"); }) +
            actBtn("Print", function () { printElement(container); }) + "</div>";
        var kv = kvRows.map(function (r) { return "<dt>" + esc(r[0]) + "</dt><dd>" + r[1] + "</dd>"; }).join("");
        container.innerHTML = (banner || "") +
            '<div class="card"><div class="card-head"><span>Share set <span class="card-sub">identifier ' + meta.identifier +
            "</span></span>" + actions + '</div><div class="card-body"><dl class="kv">' + kv + "</dl></div></div>" +
            groupCardsHtml(groups) +
            '<div class="notice notice--warn no-print">Write each share on paper (or metal) and store them in different places. ' +
            "Anyone holding enough shares can take the funds. Clear your clipboard after copying.</div>";
        container.classList.remove("display-none");
    }

    function schemeText(groups, gt) {
        if (groups.length === 1) return groups[0][0].memberThreshold + " of " + groups[0].length + " shares";
        return gt + " of " + groups.length + " groups (" + groups.map(function (g) { return g[0].memberThreshold + "/" + g.length; }).join(", ") + ")";
    }

    function hexRow(bytes) {
        return '<span class="mono">' + hex(bytes) + "</span>" + copyBtn(hex(bytes));
    }

    // Recombines a random minimal subset of a fresh set (through its words) to
    // prove it works. Decryption is re-checked too unless it would be slow.
    function verifySet(groups, gt, ems, masterSecret, passphrase) {
        function pick(arr, k) {
            var a = arr.slice();
            for (var i = a.length - 1; i > 0; i--) {
                var j = S.randomBytes(1)[0] % (i + 1);
                var t = a[i]; a[i] = a[j]; a[j] = t;
            }
            return a.slice(0, k);
        }
        var chosen = pick(groups, gt);
        var shares = [];
        chosen.forEach(function (g) { pick(g, g[0].memberThreshold).forEach(function (s) { shares.push(S.decodeShare(s.mnemonic)); }); });
        var subsetDesc = chosen.map(function (g) {
            return (groups.length > 1 ? "G" + (g[0].groupIndex + 1) + ":" : "") + "#" +
                shares.filter(function (s) { return s.groupIndex === g[0].groupIndex; }).map(function (s) { return s.memberIndex + 1; }).sort(function (a, b) { return a - b; }).join(",#");
        }).join(" ");
        return S.recoverEmsFlexible(S.analyzeShares(shares)).then(function (r) {
            var emsOk = S.bytesEqual(r.ciphertext, ems.ciphertext);
            if (!emsOk || !masterSecret || ems.iterationExponent > 4) return { ok: emsOk, full: false, subset: subsetDesc };
            return S.decrypt(r.ciphertext, passphrase, r.iterationExponent, r.identifier, r.extendable).then(function (ms) {
                return { ok: S.bytesEqual(ms, masterSecret), full: true, subset: subsetDesc };
            });
        });
    }

    function verifyBadge(v) {
        if (!v.ok) return '<span class="badge badge--bad">FAILED</span> The test recombination did not give the same secret — do not use these shares.';
        return '<span class="badge badge--ok">Verified</span> Random subset ' + esc(v.subset) +
            (v.full ? " recombined and decrypted back to the master secret." : " recombined to the same encrypted master secret.");
    }

    // ---------- Wallet preview (BIP-32 from the master secret) ----------

    function walletPreviewHtml(ms) {
        if (!BJ || !BJ.bitcoin) return "";
        if (ms.length < 16 || ms.length > 64) {
            return '<div class="notice">No BIP-32 preview: a wallet seed must be 16 – 64 bytes.</div>';
        }
        var bitcoin = BJ.bitcoin, Buffer = BJ.Buffer.Buffer, bs58check = BJ.bs58check;
        var net = bitcoin.networks.bitcoin;
        var root;
        try { root = bitcoin.HDNode.fromSeedBuffer(Buffer.from(ms), net); } catch (e) {
            return '<div class="notice notice--warn">No BIP-32 preview: ' + esc(e.message) + "</div>";
        }
        function reversion(x, ver) { var b = Buffer.from(bs58check.decode(x)); b.writeUInt32BE(ver, 0); return bs58check.encode(b); }
        function h160(node) { return bitcoin.crypto.hash160(node.getPublicKeyBuffer()); }
        var rows = [
            { name: "Legacy", sub: "BIP44 · P2PKH", path: "m/44'/0'/0'", ver: null, addr: function (n) { return n.getAddress(); } },
            { name: "Nested SegWit", sub: "BIP49 · P2SH-P2WPKH", path: "m/49'/0'/0'", ver: 0x049d7cb2, addr: function (n) {
                var redeem = Buffer.concat([Buffer.from([0x00, 0x14]), h160(n)]);
                return bitcoin.address.toBase58Check(bitcoin.crypto.hash160(redeem), net.scriptHash);
            } },
            { name: "Native SegWit", sub: "BIP84 · P2WPKH", path: "m/84'/0'/0'", ver: 0x04b24746, addr: function (n) {
                return window.encodeSegwitAddress(net.bech32, 0, h160(n));
            } },
            { name: "Taproot", sub: "BIP86 · P2TR", path: "m/86'/0'/0'", ver: null, addr: function (n) {
                if (!window.getTaprootOutputKey) return "—";
                return window.encodeSegwitAddress(net.bech32, 1, window.getTaprootOutputKey(n.getPublicKeyBuffer()));
            } }
        ];
        var body = rows.map(function (r) {
            var acct = root.derivePath(r.path);
            var xpub = acct.neutered().toBase58();
            if (r.ver) xpub = reversion(xpub, r.ver);
            var addr = r.addr(acct.derive(0).derive(0));
            return "<tr><td class=\"nowrap\"><strong>" + esc(r.name) + '</strong><span class="th-sub">' + esc(r.sub) + "</span></td>" +
                '<td class="nowrap mono">' + esc(r.path) + "/0/0</td>" +
                '<td><span class="mono">' + esc(addr) + "</span></td>" +
                '<td><span class="mono">' + esc(xpub.slice(0, 14)) + "…" + esc(xpub.slice(-8)) + "</span> " + copyBtn(xpub) + "</td></tr>";
        }).join("");
        var xprv = root.toBase58();
        return '<div class="card"><div class="card-head"><span>Bitcoin wallet preview <span class="card-sub">master secret used as the BIP-32 seed (SLIP-39 standard)</span></span></div>' +
            '<div class="card-body"><dl class="kv">' +
            "<dt>Master fingerprint</dt><dd><span class=\"mono\">" + root.getFingerprint().toString("hex") + "</span></dd>" +
            "<dt>BIP-32 root key</dt><dd><span class=\"mono\">" + esc(xprv) + "</span>" + copyBtn(xprv) + "</dd>" +
            '</dl></div><div class="table-scroll"><table class="data-table"><thead><tr><th>Type</th><th>First address</th><th></th><th>Account key</th></tr></thead>' +
            "<tbody>" + body + "</tbody></table></div></div>";
    }

    // =====================================================================
    // CREATE
    // =====================================================================

    var createScheme = SchemeEditor($("create-scheme"), "2of3");
    fillExponentSelect($("create-exp"), 1);

    var sourceRow = $("secret-source");
    sourceRow.addEventListener("click", function (e) {
        var b = e.target.closest(".pill");
        if (!b) return;
        setPills(sourceRow, "data-source", b.getAttribute("data-source"));
        document.querySelectorAll("#tab-create .source-pane").forEach(function (p) {
            p.classList.toggle("display-none", p.getAttribute("data-pane") !== b.getAttribute("data-source"));
        });
    });
    var strengthRow = $("strength-row");
    strengthRow.addEventListener("click", function (e) {
        var b = e.target.closest(".pill");
        if (b) setPills(strengthRow, "data-bits", b.getAttribute("data-bits"));
    });

    function hexInfo() {
        var el = $("secret-hex"), info = $("secret-hex-info");
        var v = el.value.trim();
        el.classList.remove("is-invalid");
        if (!v) { info.textContent = "16 – 64 bytes, an even number of bytes (128, 160, 192 … 512 bits)."; return; }
        try {
            var b = S.hexToBytes(v);
            var okLen = b.length >= 16 && b.length <= 64 && b.length % 2 === 0;
            el.classList.toggle("is-invalid", !okLen);
            var words = 7 + Math.ceil(b.length * 8 / 10); // 7 metadata words + the padded value
            info.textContent = b.length + " bytes (" + (b.length * 8) + " bits)" + (okLen ? " → " + words + "-word shares." : " — must be 16 – 64 bytes and an even number of bytes.");
        } catch (e) {
            el.classList.add("is-invalid");
            info.textContent = "Not valid hex.";
        }
    }
    $("secret-hex").addEventListener("input", hexInfo);

    function readMasterSecret() {
        var src = pillValue(sourceRow, "data-source");
        if (src === "random") {
            var bits = parseInt(pillValue(strengthRow, "data-bits"), 10);
            return Promise.resolve({ ms: S.randomBytes(bits / 8), desc: "Random " + bits + "-bit" });
        }
        if (src === "hex") {
            var v = $("secret-hex").value.trim();
            if (!v) return Promise.reject(new Error("Enter the master secret as hex."));
            var b = S.hexToBytes(v);
            if (b.length < 16 || b.length > 64 || b.length % 2) {
                return Promise.reject(new Error("The master secret must be 16 – 64 bytes with an even number of bytes (got " + b.length + ")."));
            }
            return Promise.resolve({ ms: b, desc: "Entered as hex" });
        }
        var phrase = $("bip39-phrase").value;
        if (!phrase.trim()) return Promise.reject(new Error("Enter the BIP-39 recovery phrase."));
        return B39.validate(phrase).then(function (v) {
            if (!v.ok) throw new Error(v.error);
            var pass = $("bip39-pass").value;
            return B39.mnemonicToSeed(phrase, pass).then(function (seed) {
                return { ms: seed, desc: "BIP-39 seed from a " + v.words.length + "-word phrase" + (pass ? " + passphrase" : "") };
            });
        });
    }

    function roundProgress(id, verb) {
        return function (done, total) { setBusy(id, verb + " — PBKDF2 round " + Math.min(done + 1, total) + " of " + total + "…"); };
    }

    $("create-btn").addEventListener("click", function () {
        var btn = this;
        hideError("create-error");
        var scheme, pass, e, id, ext;
        try {
            scheme = createScheme.get();
            pass = $("create-pass").value;
            S.asciiBytes(pass);
            e = parseInt($("create-exp").value, 10);
            ext = $("create-ext").checked;
            var idv = $("create-id").value.trim();
            id = null;
            if (idv) {
                if (!/^\d+$/.test(idv) || +idv > 32767) throw new Error("The identifier must be a number from 0 to 32767.");
                id = +idv;
            }
        } catch (err) { showError("create-error", err.message); return; }

        btn.disabled = true;
        setBusy("create-status", "Preparing…");
        var src;
        readMasterSecret().then(function (r) {
            src = r;
            setBusy("create-status", "Encrypting master secret…");
            return S.generateShares({
                groupThreshold: scheme.groupThreshold, groups: scheme.groups, masterSecret: r.ms,
                passphrase: pass, extendable: ext, iterationExponent: e, identifier: id,
                onRound: roundProgress("create-status", "Encrypting master secret")
            });
        }).then(function (res) {
            setBusy("create-status", "Verifying…");
            return verifySet(res.groups, scheme.groupThreshold, res.ems, src.ms, pass).then(function (v) { return { res: res, v: v }; });
        }).then(function (x) {
            var res = x.res, ems = res.ems;
            var meta = { identifier: ems.identifier, extendable: ems.extendable, iterationExponent: ems.iterationExponent, groupThreshold: scheme.groupThreshold };
            var words = res.groups[0][0].words.length;
            renderShareSet($("create-output"), res.groups, meta, [
                ["Scheme", esc(schemeText(res.groups, scheme.groupThreshold)) + " · " + words + " words per share"],
                ["Master secret", hexRow(src.ms) + ' <span class="card-sub">' + esc(src.desc) + " · " + (src.ms.length * 8) + " bits</span>"],
                ["Encrypted (EMS)", hexRow(ems.ciphertext)],
                ["Passphrase", pass ? "Yes — " + plural(pass.length, "character") + ". Without it the shares open a different, empty wallet." : "None"],
                ["Encryption", esc(describeExp(ems.iterationExponent)) + " · " + (ems.extendable ? "extendable backup" : "non-extendable (identifier is part of the salt)")],
                ["Check", verifyBadge(x.v)]
            ]);
            setBusy("create-status", "");
            $("create-output").scrollIntoView({ behavior: "smooth", block: "start" });
        }).catch(function (err) {
            setBusy("create-status", "");
            showError("create-error", err.message);
        }).then(function () { btn.disabled = false; });
    });

    $("create-clear").addEventListener("click", function () {
        $("secret-hex").value = "";
        $("bip39-phrase").value = "";
        $("bip39-pass").value = "";
        $("create-pass").value = "";
        $("create-id").value = "";
        hexInfo();
        hideError("create-error");
        $("create-output").innerHTML = "";
        $("create-output").classList.add("display-none");
    });

    // =====================================================================
    // RECOVER
    // =====================================================================

    var SAMPLE = {
        shares: [
            "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
            "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
            "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
            "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
            "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"
        ],
        pass: "TREZOR"
    };

    var recoverSet = null;
    var refreshRecover = debounce(function () {
        recoverSet = parseShareSet($("recover-input").value);
        renderSetStatus($("recover-status"), recoverSet);
    }, 120);
    $("recover-input").addEventListener("input", refreshRecover);

    $("recover-sample").addEventListener("click", function () {
        $("recover-input").value = "# Official SLIP-0039 test vector 17 (passphrase \"TREZOR\"): 2 of 4 groups\n" + SAMPLE.shares.join("\n");
        $("recover-pass").value = SAMPLE.pass;
        recoverSet = parseShareSet($("recover-input").value);
        renderSetStatus($("recover-status"), recoverSet);
        hideError("recover-error");
    });

    function missingDescription(a) {
        var p = a.params;
        var parts = [];
        a.groups.forEach(function (g) {
            if (!g.complete) parts.push((p.groupCount > 1 ? "group " + (g.groupIndex + 1) + " needs " : "needs ") + (g.memberThreshold - g.members.length) + " more share(s)");
        });
        if (p.groupCount > 1 && a.completeGroups < p.groupThreshold) {
            parts.unshift(a.completeGroups + " of the " + p.groupThreshold + " required groups are complete");
        }
        return "Not enough shares yet: " + parts.join("; ") + ".";
    }

    $("recover-btn").addEventListener("click", function () {
        var btn = this;
        hideError("recover-error");
        $("recover-output").classList.add("display-none");
        var set = parseShareSet($("recover-input").value);
        recoverSet = set;
        renderSetStatus($("recover-status"), set);
        var a = set.analysis;
        if (!a.params) {
            showError("recover-error", set.entries.length ? "None of the pasted shares is valid — see the list above." : "Paste your shares first.");
            return;
        }
        if (!a.complete) { showError("recover-error", missingDescription(a)); return; }
        var pass = $("recover-pass").value;
        try { S.asciiBytes(pass); } catch (err) { showError("recover-error", err.message); return; }

        btn.disabled = true;
        setBusy("recover-progress", "Combining shares…");
        var emsInfo;
        S.recoverEmsFlexible(a).then(function (ems) {
            emsInfo = ems;
            setBusy("recover-progress", "Decrypting…");
            return S.decrypt(ems.ciphertext, pass, ems.iterationExponent, ems.identifier, ems.extendable,
                roundProgress("recover-progress", "Decrypting master secret"));
        }).then(function (ms) {
            // Mark shares that didn't fit the recovered polynomial
            emsInfo.report.groups.forEach(function (gr) {
                var g = a.groups.get(gr.groupIndex);
                (gr.inconsistent || []).forEach(function (mi) {
                    g.members.forEach(function (m) {
                        if (m.share.memberIndex === mi) {
                            m.entry.inconsistent = "Doesn't agree with the other shares of this group (corrupted, or from a different share set) — it was not used.";
                        }
                    });
                });
            });
            renderSetStatus($("recover-status"), set);
            return renderRecovered(ms, emsInfo, a, pass);
        }).catch(function (err) {
            showError("recover-error", err.message);
        }).then(function () {
            setBusy("recover-progress", "");
            btn.disabled = false;
        });
    });

    function renderRecovered(ms, ems, a, pass) {
        var used = ems.report.groups.filter(function (g) { return g.ok && (!ems.report.usedGroups || ems.report.usedGroups.indexOf(g.groupIndex) !== -1); })
            .map(function (g) {
                return (a.params.groupCount > 1 ? "Group " + (g.groupIndex + 1) + ": " : "") + "share #" +
                    g.used.slice().sort(function (x, y) { return x - y; }).map(function (i) { return i + 1; }).join(", #");
            }).join(" · ");
        var warnings = [];
        ems.report.groups.forEach(function (g) {
            if (g.inconsistent && g.inconsistent.length) {
                warnings.push((a.params.groupCount > 1 ? "Group " + (g.groupIndex + 1) + ": " : "") + "share #" +
                    g.inconsistent.map(function (i) { return i + 1; }).join(", #") + " didn't agree with the others and was ignored.");
            }
            if (!g.ok) warnings.push("Group " + (g.groupIndex + 1) + " could not be recovered: " + g.error);
        });
        if (ems.report.inconsistentGroups && ems.report.inconsistentGroups.length) {
            warnings.push("Group " + ems.report.inconsistentGroups.map(function (i) { return i + 1; }).join(", ") + " didn't agree with the other groups and was ignored.");
        }

        return interpretationsHtml(ms).then(function (interp) {
            var out = $("recover-output");
            out.innerHTML =
                (warnings.length ? '<div class="notice notice--warn">' + warnings.map(esc).join("<br>") + "</div>" : "") +
                '<div class="card"><div class="card-head"><span>Recovered master secret <span class="card-sub">' + (ms.length * 8) + " bits</span></span>" +
                '<div class="card-actions">' + copyBtn(hex(ms), "Copy hex") + "</div></div>" +
                '<div class="card-body"><dl class="kv">' +
                "<dt>Master secret</dt><dd><span class=\"mono\">" + hex(ms) + "</span></dd>" +
                "<dt>Encrypted (EMS)</dt><dd>" + hexRow(ems.ciphertext) + "</dd>" +
                "<dt>Passphrase</dt><dd>" + (pass ? "Used (" + plural(pass.length, "character") + ")" : "None (empty)") +
                ' <span class="card-sub">— not verifiable; check the addresses below</span></dd>' +
                "<dt>Share set</dt><dd>Identifier " + ems.identifier + " · " + (ems.extendable ? "extendable" : "non-extendable") + " · " + esc(describeExp(ems.iterationExponent)) + "</dd>" +
                "<dt>Shares used</dt><dd>" + esc(used) + "</dd>" +
                "</dl></div></div>" +
                walletPreviewHtml(ms) + interp;
            out.classList.remove("display-none");
            out.scrollIntoView({ behavior: "smooth", block: "start" });
        });
    }

    function interpretationsHtml(ms) {
        var notes = [];
        var p = Promise.resolve();
        if (ms.length === 64) {
            notes.push("A 64-byte master secret is the size of a BIP-39 seed, so these shares were most likely made by converting a BIP-39 wallet. " +
                "The original 12/24-word phrase cannot be derived back from the seed, but the wallet above is the same one.");
        }
        if ([16, 20, 24, 28, 32].indexOf(ms.length) !== -1 && window.bipWords) {
            p = B39.entropyToMnemonic(ms).then(function (m) {
                if (m) {
                    notes.push("<strong>Non-standard reading.</strong> Some third-party tools split BIP-39 <em>entropy</em> instead of the seed. " +
                        "If these shares came from such a tool, the BIP-39 phrase would be:<div class=\"mono\" style=\"margin:6px 0\">" + esc(m) + "</div>" +
                        copyBtn(m, "Copy phrase") + " Standard SLIP-39 wallets (Trezor and others) use the master secret directly as the seed, as in the preview above.");
                }
            });
        }
        return p.then(function () {
            if (!notes.length) return "";
            return '<details class="card"><summary class="card-head" style="cursor:pointer">Other interpretations</summary>' +
                '<div class="card-body" style="font-size:12.5px;line-height:1.55">' + notes.join("<hr style=\"border:none;border-top:1px solid var(--border);margin:10px 0\">") + "</div></details>";
        });
    }

    $("recover-clear").addEventListener("click", function () {
        $("recover-input").value = "";
        $("recover-pass").value = "";
        recoverSet = null;
        $("recover-status").innerHTML = "";
        hideError("recover-error");
        $("recover-output").innerHTML = "";
        $("recover-output").classList.add("display-none");
    });

    // =====================================================================
    // INSPECT & REPAIR
    // =====================================================================

    var inspectDeep = false;

    function segClass(i, n) {
        if (i < 2) return "seg-id";
        if (i < 4) return "seg-param";
        if (i >= n - 3) return "seg-check";
        return "seg-value";
    }

    function bits10(i) { var s = i.toString(2); return "0000000000".slice(s.length) + s; }

    function runInspect() {
        var out = $("inspect-output");
        var text = $("inspect-input").value;
        if (!text.trim()) { out.innerHTML = ""; out.classList.add("display-none"); return; }
        var resolved = S.resolveWords(text);
        var unknown = resolved.filter(function (r) { return r.index === null; });
        var html = "";
        var needsRepair = false;

        if (unknown.length) {
            needsRepair = true;
            var unk = unknown.filter(function (r) { return r.status === "unknown"; });
            html += '<div class="notice notice--error"><strong>' + plural(unknown.length, "word") + " can't be read.</strong> " +
                (unk.length ? unk.map(function (r) {
                    return "“" + esc(r.token) + "” is not in the SLIP-39 wordlist (closest: " + esc(r.suggestions.slice(0, 4).join(", ")) + ")";
                }).join("; ") + ". " : "") +
                (unknown.length <= 3 ? "They are treated as unknown words below." : "The checksum can restore at most 3 unknown words.") + "</div>";
            html += '<div class="card"><div class="card-head"><span>Words <span class="card-sub">' + resolved.length + " entered</span></span></div>" +
                '<div class="card-body">' + wordGrid(resolved.map(function (r) { return r.word || r.token; }), function (i) {
                    return resolved[i].index === null ? "is-unknown" : resolved[i].status === "fuzzy" ? "is-guess" : "";
                }) + "</div></div>";
        } else {
            var indices = resolved.map(function (r) { return r.index; });
            var r = S.inspectIndices(indices);
            needsRepair = !r.ok;
            html += r.ok
                ? '<div class="notice notice--ok"><strong>Valid SLIP-39 share.</strong> The checksum and all structural checks pass.</div>'
                : '<div class="notice notice--error"><strong>Invalid share.</strong> ' +
                  esc(r.checks.filter(function (c) { return !c.pass; }).map(function (c) { return c.label + ": " + c.detail; }).join(" · ")) + "</div>";
            var fuzzy = resolved.filter(function (x) { return x.status === "fuzzy"; });
            if (fuzzy.length) {
                html += '<div class="notice notice--warn">Read by their first four letters: ' +
                    fuzzy.map(function (x) { return "“" + esc(x.token) + "” → " + esc(x.word); }).join(", ") + "</div>";
            }
            if (r.identifier !== undefined) html += fieldsCard(r, r.ok);
            html += '<div class="card"><div class="card-head"><span>Words <span class="card-sub">' + r.wordCount +
                " words · 10 bits each</span></span>" + (r.ok ? '<div class="card-actions">' + copyBtn(r.words.join(" ")) + "</div>" : "") + "</div>" +
                '<div class="card-body"><div class="seg-legend"><span class="l-id">identifier · flag · exponent</span>' +
                '<span class="l-param">group &amp; member parameters</span><span class="l-value">share value</span><span class="l-check">checksum</span></div>' +
                '<div class="word-grid">' + r.words.map(function (w, i) {
                    return '<span class="w ' + segClass(i, r.wordCount) + '" title="index ' + indices[i] + " · " + bits10(indices[i]) + '"><span class="n">' + (i + 1) + "</span>" + esc(w) +
                        '<span class="bits">' + indices[i] + "</span></span>";
                }).join("") + "</div></div></div>";
            html += '<div class="card"><div class="card-head"><span>Checks</span></div><div class="card-body"><div class="checks">' +
                r.checks.map(function (c) {
                    return '<div class="c ' + (c.pass ? "pass" : "fail") + '"><span class="ci">' + (c.pass ? "✓" : "✗") + '</span><span class="cl">' +
                        esc(c.label) + '</span><span class="cd">' + esc(c.detail) + "</span></div>";
                }).join("") + "</div></div></div>";
        }

        if (needsRepair) html += repairHtml(resolved);
        out.innerHTML = html;
        out.classList.remove("display-none");
    }

    function fieldsCard(r, ok) {
        var rows = [
            ["Identifier", r.identifier + ' <span class="card-sub">0x' + r.identifier.toString(16).padStart(4, "0") + " — the same on every share of a set</span>"],
            ["Extendable flag", (r.extendable ? "1 — extendable backup" : "0 — non-extendable (identifier is part of the encryption salt)") +
                ' <span class="card-sub">checksum string “' + esc(r.customization) + "”</span>"],
            ["Iteration exponent", r.iterationExponent + ' <span class="card-sub">' + fmt(r.iterations) + " PBKDF2-SHA256 iterations (" + fmt(r.iterations / 4) + " per Feistel round)</span>"],
            ["Group", (r.groupIndex + 1) + " of " + r.groupCount + ' <span class="card-sub">' + r.groupThreshold + " group" + (r.groupThreshold === 1 ? "" : "s") + " needed to recover</span>"],
            ["Member share", "#" + (r.memberIndex + 1) + ' <span class="card-sub">' + r.memberThreshold + " share" + (r.memberThreshold === 1 ? "" : "s") + " of this group needed</span>"],
            ["Group prefix", '<span class="mono">' + esc(r.words.slice(0, 3).join(" ")) + '</span> <span class="card-sub">all shares of this group start with these words</span>']
        ];
        if (r.value) {
            rows.push(["Share value", hexRow(r.value) + ' <span class="card-sub">' + r.valueBits + " bits → a " + r.valueBits + "-bit master secret</span>"]);
            rows.push(["Padding", r.paddingBits + " zero bit" + (r.paddingBits === 1 ? "" : "s")]);
        }
        return '<div class="card"><div class="card-head"><span>Decoded fields' + (ok ? "" : ' <span class="card-sub">from the words as entered — may be wrong</span>') +
            "</span></div>" + '<div class="card-body"><dl class="kv">' +
            rows.map(function (x) { return "<dt>" + esc(x[0]) + "</dt><dd>" + x[1] + "</dd>"; }).join("") + "</dl></div></div>";
    }

    function describeCandidate(c, resolved) {
        var typed = resolved.map(function (r) { return r.word || r.token; });
        function word(i) { return "“" + c.words[i] + "”"; }
        function was(i) { return typed[i] === "?" ? "" : " (was “" + typed[i] + "”)"; }
        switch (c.kind) {
            case "substitution": return "Word " + (c.positions[0] + 1) + " → " + word(c.positions[0]) + was(c.positions[0]);
            case "erasure":
            case "erasure+substitution":
            case "double-substitution":
                return c.positions.slice().sort(function (a, b) { return a - b; }).map(function (p) { return "word " + (p + 1) + " → " + word(p) + was(p); }).join(", ").replace(/^w/, "W");
            case "erasure+missing": return "Unknown words filled and a missing word inserted at position " + (c.positions[c.positions.length - 1] + 1);
            case "transposition": return "Words " + (c.positions[0] + 1) + " and " + (c.positions[1] + 1) + " swapped back";
            case "missing": return "Missing word inserted at position " + (c.positions[0] + 1) + ": " + word(c.positions[0]);
            case "extra": return "Extra word " + (c.positions[0] + 1) + " (“" + typed[c.positions[0]] + "”) removed";
            default: return c.kind;
        }
    }

    function changedPositions(c) {
        if (c.kind === "extra" || c.kind === "transposition") return c.kind === "transposition" ? c.positions : [];
        return c.positions;
    }

    function similarity(c, resolved) {
        // smallest edit distance between what was typed and the proposed word(s)
        if (["substitution", "double-substitution", "erasure+substitution"].indexOf(c.kind) === -1) return null;
        var d = 0;
        c.positions.forEach(function (p) {
            var t = resolved[p] && (resolved[p].word || resolved[p].token);
            if (t && t !== "?") d += S.editDistance(t, c.words[p]);
        });
        return d;
    }

    function repairHtml(resolved) {
        var result;
        try {
            result = S.repairCandidates(resolved, { deep: inspectDeep });
        } catch (e) {
            return '<div class="notice notice--error">' + esc(e.message) + "</div>";
        }
        var cands = result.candidates.slice();
        cands.forEach(function (c) { c.sim = similarity(c, resolved); });
        cands.sort(function (a, b) {
            var sa = a.sim == null ? 99 : a.sim, sb = b.sim == null ? 99 : b.sim;
            return sa - sb;
        });
        var deepToggle = '<label class="check no-print" style="margin-top:10px"><input type="checkbox" id="inspect-deep"' + (inspectDeep ? " checked" : "") +
            "><span><strong>Also try two wrong words.</strong> Wider search; because two unknown words use up most of the checksum, " +
            "it can return a few false matches — only accept one that matches your written share.</span></label>";

        var body;
        if (result.note) {
            body = '<div class="card-body">' + esc(result.note) + "</div>";
        } else if (!cands.length) {
            body = '<div class="card-body" style="font-size:13px;line-height:1.55">No correction found that explains a single error ' +
                "(one wrong, missing, extra or swapped word" + (inspectDeep ? ", or two wrong words" : "") + "). Check the words against your copy, " +
                "or mark words you're unsure of with <code>?</code> (up to 3)." + deepToggle + "</div>";
        } else {
            body = cands.map(function (c) {
                var info = S.inspectIndices(c.indices);
                var changed = changedPositions(c);
                var meta = "Group " + (info.groupIndex + 1) + " of " + info.groupCount + " · share #" + (info.memberIndex + 1) +
                    " · identifier " + info.identifier + " · " + info.valueBits + "-bit";
                return '<div class="cand"><div class="cand-head"><span class="cand-desc">' + esc(describeCandidate(c, resolved)) +
                    (c.sim != null && c.sim <= 2 ? ' <span class="badge badge--ok">similar spelling</span>' : "") +
                    '<div class="card-sub" style="font-weight:500;margin-top:3px">' + esc(meta) + "</div></span>" +
                    '<span class="card-actions">' + copyBtn(c.words.join(" ")) +
                    actBtn("Use this", function () { $("inspect-input").value = c.words.join(" "); runInspect(); }) + "</span></div>" +
                    wordGrid(c.words, function (i) { return changed.indexOf(i) !== -1 ? "is-changed" : ""; }) + "</div>";
            }).join("") + '<div class="cand">' + deepToggle + "</div>";
        }
        return '<div class="card"><div class="card-head"><span>Possible corrections <span class="card-sub">' +
            (cands.length ? plural(cands.length, "candidate") : "none") + "</span></span></div>" +
            '<div class="notice notice--info" style="margin:12px 14px 0">These are suggestions derived from the RS1024 checksum, not facts. ' +
            "SLIP-39 deliberately leaves the final correction to you: compare each candidate with the share you wrote down. " +
            "The identifier and first words must match your other shares of the same set." +
            (resolved.filter(function (r) { return r.index === null; }).length === 3 && resolved[1] && resolved[1].index === null
                ? " With three unknown words including word 2 (it carries the extendable flag) two candidates can be valid — the right one has the same first two words as your other shares."
                : "") + "</div>" +
            body + "</div>";
    }

    $("inspect-input").addEventListener("input", debounce(runInspect, 150));
    $("inspect-output").addEventListener("change", function (e) {
        if (e.target.id === "inspect-deep") { inspectDeep = e.target.checked; runInspect(); }
    });

    // =====================================================================
    // EXTEND & REGENERATE
    // =====================================================================

    var reshareScheme = SchemeEditor($("reshare-scheme"), "2of3");
    fillExponentSelect($("reshare-exp"), 1);
    var reshareSet = null;
    var modeRow = $("reshare-mode");

    function reshareMode() { return pillValue(modeRow, "data-mode"); }

    modeRow.addEventListener("click", function (e) {
        var b = e.target.closest(".pill");
        if (!b) return;
        setPills(modeRow, "data-mode", b.getAttribute("data-mode"));
        document.querySelectorAll("#tab-reshare .mode-pane").forEach(function (p) {
            p.classList.toggle("display-none", p.getAttribute("data-pane") !== b.getAttribute("data-mode"));
        });
        $("reshare-btn").textContent = { newset: "Create new share set", member: "Regenerate share", group: "Rebuild group" }[b.getAttribute("data-mode")];
        hideError("reshare-error");
        updateReshareControls();
    });

    $("reshare-reenc").addEventListener("change", updateReshareControls);
    $("reshare-same").addEventListener("change", function () {
        var np = $("reshare-newpass");
        np.disabled = this.checked;
        np.placeholder = this.checked ? "same as current" : "empty for none";
        if (this.checked) np.value = "";
        else np.focus();
    });

    function updateReshareControls() {
        var set = reshareSet;
        var a = set && set.analysis;
        var info = $("reshare-enc-info"), enc = $("reshare-enc");
        if (!a || !a.params) {
            info.classList.add("display-none");
            enc.classList.add("display-none");
        } else {
            enc.classList.remove("display-none");
            info.classList.remove("display-none");
            if (a.params.extendable) {
                info.innerHTML = "These shares are <strong>extendable</strong>: the new set can reuse the encrypted master secret as-is, so " +
                    "no passphrase is needed and every passphrase keeps opening the same wallet.";
                $("reshare-reenc-wrap").classList.remove("display-none");
                $("reshare-pass-fields").classList.toggle("display-none", !$("reshare-reenc").checked);
            } else {
                info.innerHTML = "These shares are <strong>non-extendable</strong> (made before the flag existed, or with it off): the identifier is " +
                    "part of the encryption, so a set with a new identifier must be re-encrypted. Enter the current passphrase (empty if none). " +
                    "The new set will be extendable.";
                $("reshare-reenc-wrap").classList.add("display-none");
                $("reshare-pass-fields").classList.remove("display-none");
            }
            if ($("reshare-exp").getAttribute("data-set") !== String(a.params.identifier)) {
                fillExponentSelect($("reshare-exp"), a.params.iterationExponent);
                $("reshare-exp").setAttribute("data-set", String(a.params.identifier));
            }
        }

        // group / member selects
        var gSel = $("member-group"), mSel = $("member-index"), grSel = $("group-index");
        if (!a || !a.params) {
            gSel.innerHTML = grSel.innerHTML = '<option value="">— paste shares first —</option>';
            mSel.innerHTML = "";
            return;
        }
        var p = a.params;
        var prevG = gSel.value, prevGr = grSel.value;
        var opts = "", gopts = "", firstComplete = null;
        for (var gi = 0; gi < p.groupCount; gi++) {
            var g = a.groups.get(gi);
            var have = g ? g.members.length : 0;
            var st = g ? have + "/" + g.memberThreshold + (g.complete ? " ✓" : "") : "no shares";
            if (g && g.complete && firstComplete === null) firstComplete = gi;
            opts += '<option value="' + gi + '"' + (g && g.complete ? "" : " disabled") + ">Group " + (gi + 1) + " — " + st + "</option>";
            gopts += '<option value="' + gi + '">Group ' + (gi + 1) + " — " + st + "</option>";
        }
        gSel.innerHTML = opts;
        grSel.innerHTML = gopts;
        if (prevG !== "" && a.groups.get(+prevG) && a.groups.get(+prevG).complete) gSel.value = prevG;
        else if (firstComplete !== null) gSel.value = String(firstComplete);
        if (prevGr !== "" && +prevGr < p.groupCount) grSel.value = prevGr;
        else {
            var firstMissing = 0;
            for (var k = 0; k < p.groupCount; k++) { if (!a.groups.get(k) || !a.groups.get(k).complete) { firstMissing = k; break; } }
            grSel.value = String(firstMissing);
        }
        updateMemberSelect();
    }

    function updateMemberSelect() {
        var a = reshareSet && reshareSet.analysis;
        var mSel = $("member-index");
        var g = a && a.groups.get(+$("member-group").value);
        if (!g || !g.complete) { mSel.innerHTML = '<option value="">— needs a complete group —</option>'; return; }
        var have = g.members.map(function (m) { return m.share.memberIndex; });
        var prev = mSel.value;
        var firstMissing = null, html = "";
        for (var i = 0; i < 16; i++) {
            var has = have.indexOf(i) !== -1;
            if (!has && firstMissing === null) firstMissing = i;
            html += '<option value="' + i + '">Share #' + (i + 1) + (has ? " — you have it (consistency check)" : "") + "</option>";
        }
        mSel.innerHTML = html;
        mSel.value = prev !== "" && +prev < 16 ? prev : String(firstMissing === null ? 0 : firstMissing);
    }
    $("member-group").addEventListener("change", updateMemberSelect);

    var refreshReshare = debounce(function () {
        reshareSet = parseShareSet($("reshare-input").value);
        renderSetStatus($("reshare-status"), reshareSet);
        updateReshareControls();
    }, 120);
    $("reshare-input").addEventListener("input", refreshReshare);

    function newIdentifier(old) {
        var id;
        do { id = S.randomIdentifier(); } while (id === old);
        return id;
    }

    $("reshare-btn").addEventListener("click", function () {
        var btn = this;
        hideError("reshare-error");
        var set = parseShareSet($("reshare-input").value);
        reshareSet = set;
        renderSetStatus($("reshare-status"), set);
        updateReshareControls();
        var a = set.analysis;
        if (!a.params) { showError("reshare-error", set.entries.length ? "None of the pasted shares is valid." : "Paste your existing shares first."); return; }
        var mode = reshareMode();
        var job;
        try {
            if (mode === "newset") job = newSetJob(a);
            else if (mode === "member") job = memberJob(a);
            else job = groupJob(a);
        } catch (err) { showError("reshare-error", err.message); return; }
        btn.disabled = true;
        setBusy("reshare-progress", "Working…");
        job().catch(function (err) { showError("reshare-error", err.message); })
            .then(function () { setBusy("reshare-progress", ""); btn.disabled = false; });
    });

    function newSetJob(a) {
        if (!a.complete) throw new Error(missingDescription(a) + " A new share set needs a full recovery set.");
        var scheme = reshareScheme.get();
        var reenc = !a.params.extendable || $("reshare-reenc").checked;
        var oldPass = $("reshare-oldpass").value;
        var samePass = $("reshare-same").checked;
        var newPass = samePass ? oldPass : $("reshare-newpass").value;
        var newExp = parseInt($("reshare-exp").value, 10);
        if (reenc) { S.asciiBytes(oldPass); S.asciiBytes(newPass); }
        return function () {
            return S.recoverEmsFlexible(a).then(function (ems) {
                var id = newIdentifier(ems.identifier);
                if (!reenc) {
                    var nems = { identifier: id, extendable: true, iterationExponent: ems.iterationExponent, ciphertext: ems.ciphertext };
                    return S.splitEms(scheme.groupThreshold, scheme.groups, nems).then(function (groups) {
                        return verifySet(groups, scheme.groupThreshold, nems, null, "").then(function (v) {
                            renderNewSet(groups, nems, scheme, v, ems, "Encryption kept — no passphrase was needed. Every passphrase opens the same wallet as with the old shares.");
                        });
                    });
                }
                setBusy("reshare-progress", "Decrypting…");
                return S.decrypt(ems.ciphertext, oldPass, ems.iterationExponent, ems.identifier, ems.extendable,
                    roundProgress("reshare-progress", "Decrypting with the current passphrase")).then(function (ms) {
                    return S.generateShares({
                        groupThreshold: scheme.groupThreshold, groups: scheme.groups, masterSecret: ms, passphrase: newPass,
                        extendable: true, iterationExponent: newExp, identifier: id,
                        onRound: roundProgress("reshare-progress", "Re-encrypting")
                    }).then(function (res) {
                        return verifySet(res.groups, scheme.groupThreshold, res.ems, ms, newPass).then(function (v) {
                            renderNewSet(res.groups, res.ems, scheme, v, ems,
                                "Re-encrypted with " + (samePass ? (oldPass ? "the same passphrase" : "no passphrase (as before)") : newPass ? "the new passphrase" : "no passphrase") +
                                " and " + describeExp(newExp) + ". " +
                                "There is no way to check the current passphrase you entered — if it was wrong, the new set protects a different (empty) wallet. " +
                                "Recover the new set once and compare the addresses before relying on it.");
                        });
                    });
                });
            });
        };
    }

    function renderNewSet(groups, ems, scheme, v, oldEms, note) {
        var meta = { identifier: ems.identifier, extendable: ems.extendable, iterationExponent: ems.iterationExponent, groupThreshold: scheme.groupThreshold };
        renderShareSet($("reshare-output"), groups, meta, [
            ["Scheme", esc(schemeText(groups, scheme.groupThreshold)) + " · " + groups[0][0].words.length + " words per share"],
            ["Identifier", ems.identifier + ' <span class="card-sub">new (old set: ' + oldEms.identifier + ") — shares of the two sets can't be mixed</span>"],
            ["Encrypted (EMS)", hexRow(ems.ciphertext)],
            ["Encryption", esc(note)],
            ["Check", verifyBadge(v)]
        ]);
        $("reshare-output").scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function memberJob(a) {
        var gi = $("member-group").value;
        var g = gi !== "" && a.groups.get(+gi);
        if (!g || !g.complete) {
            throw new Error("Regenerating a share needs a complete group: " + (a.groups.size ? "add enough shares of one group (its member threshold)." : "paste shares first."));
        }
        var mi = parseInt($("member-index").value, 10);
        return function () {
            return S.regenerateMemberShare(g.members.map(function (m) { return m.share; }), mi).then(function (share) {
                var existing = g.members.filter(function (m) { return m.share.memberIndex === mi; })[0];
                var banner;
                if (existing) {
                    banner = existing.share.words.join(" ") === share.mnemonic
                        ? '<div class="notice notice--ok"><strong>Consistent.</strong> The regenerated share #' + (mi + 1) + " is identical to the one you entered.</div>"
                        : '<div class="notice notice--error"><strong>Mismatch.</strong> Share #' + (mi + 1) + " as entered differs from what the other shares imply — one of them is corrupted.</div>";
                } else {
                    banner = '<div class="notice notice--info">If the original group had a share #' + (mi + 1) + ", this is it, word for word. " +
                        "Otherwise it is a new, valid share for the group.</div>";
                }
                var out = $("reshare-output");
                out.innerHTML = banner + '<div class="card group-card"><div class="card-head"><span>Regenerated share <span class="card-sub">' +
                    (share.groupCount > 1 ? "group " + (share.groupIndex + 1) + " · " : "") + share.memberThreshold + " of this group's shares needed</span></span></div>" +
                    '<div class="share-cards">' + shareCardHtml(share, "Share #" + (mi + 1), share.groupCount > 1 ? "group " + (share.groupIndex + 1) : "") + "</div></div>";
                out.classList.remove("display-none");
            });
        };
    }

    function groupJob(a) {
        if (!a.complete) throw new Error(missingDescription(a) + " Rebuilding a group needs a full recovery set.");
        var gi = parseInt($("group-index").value, 10);
        var t = parseInt($("group-t").value, 10), n = parseInt($("group-n").value, 10);
        S.validateScheme(1, [[t, n]]);
        var existing = a.groups.get(gi);
        return function () {
            return S.recoverEmsFlexible(a).then(function (ems) {
                return S.regenerateGroup(ems, gi, t, n).then(function (shares) {
                    var exact = t === 1 && n === 1;
                    var banner = exact
                        ? '<div class="notice notice--ok">A 1-of-1 group has a single, fully determined share' +
                          (existing && existing.memberThreshold !== 1 ? "" : " — if group " + (gi + 1) + " was 1-of-1, this is its original share, word for word") + ".</div>"
                        : '<div class="notice notice--warn"><strong>New member set for group ' + (gi + 1) + ".</strong> These shares work together with the other groups, " +
                          "but must not be mixed with any surviving shares of the old group " + (gi + 1) + " (same first words, different polynomial). Destroy those.</div>";
                    if (existing && existing.memberThreshold !== t) {
                        banner += '<div class="notice notice--warn">You already have shares of group ' + (gi + 1) + " with threshold " + existing.memberThreshold +
                            "; the rebuilt group uses " + t + ".</div>";
                    }
                    var out = $("reshare-output");
                    out.innerHTML = banner + groupCardsHtml([shares], { forceGroupTitle: true });
                    out.classList.remove("display-none");
                });
            });
        };
    }

    $("reshare-clear").addEventListener("click", function () {
        $("reshare-input").value = "";
        $("reshare-oldpass").value = "";
        $("reshare-newpass").value = "";
        reshareSet = null;
        $("reshare-status").innerHTML = "";
        hideError("reshare-error");
        $("reshare-output").innerHTML = "";
        $("reshare-output").classList.add("display-none");
        updateReshareControls();
    });
    updateReshareControls();

    // =====================================================================
    // WORDLIST
    // =====================================================================

    function renderWordlist() {
        var q = $("wordlist-search").value.trim().toLowerCase();
        var list = S.WORDLIST.map(function (w, i) { return { w: w, i: i }; });
        if (q) {
            if (/^\d+$/.test(q)) list = list.filter(function (x) { return x.i === +q; });
            else {
                var starts = list.filter(function (x) { return x.w.indexOf(q) === 0; });
                var contains = list.filter(function (x) { return x.w.indexOf(q) > 0; });
                list = starts.concat(contains);
            }
        }
        $("wordlist-count").textContent = q ? list.length + " of 1024 words" : "1024 words";
        $("wordlist-grid").innerHTML = list.length ? list.map(function (x) {
            return '<span class="wi" title="index ' + x.i + " · " + bits10(x.i) + '">' +
                '<span class="n">' + x.i + "</span><span><b>" + x.w.slice(0, 4) + "</b>" + x.w.slice(4) + "</span></span>";
        }).join("") : '<div class="empty">No SLIP-39 word matches “' + esc(q) + "”.</div>";
    }
    $("wordlist-search").addEventListener("input", debounce(renderWordlist, 80));
    renderWordlist();

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
})();
