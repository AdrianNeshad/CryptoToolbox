// This file expects a global array `window.bipWords`. English (bip39_english.js)
// is loaded up front in the page <head>; other languages are loaded on demand
// when picked from the language dropdown.

const grid = document.getElementById("word-grid");
const emptyState = document.getElementById("empty-state");
const resultCount = document.getElementById("result-count");
const searchInput = document.getElementById("search-input");
const languageSelect = document.getElementById("language-select");

let wordlist = window.bipWords || [];

// Cache of already-loaded wordlists, keyed by language value. English is the
// default and is available immediately.
const wordlistCache = { english: wordlist };
let currentLang = "english";

function escapeHtml(str) {
    return str.replace(/[&<>"']/g, (c) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
    }[c]));
}

// Fold a single character for searching: decompose (NFD) and strip Latin
// combining diacritics, then lowercase. The official BIP39 wordlists are stored
// in decomposed (NFD) form and typed input is usually composed (NFC), so folding
// both sides lets a query match regardless of normalization. It also makes
// accents optional (e.g. "abaco" matches "ábaco"), which is what the BIP39 spec
// recommends for languages like Spanish and French. Non-Latin combining marks
// (e.g. Japanese dakuten, Hangul jamo) are left intact, so those scripts still
// match exactly and consistently.
function foldChar(ch) {
    return ch.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
}

function foldForSearch(str) {
    return str.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
}

function highlight(word, query) {
    const foldedQuery = foldForSearch(query);
    if (!foldedQuery) return escapeHtml(word);

    // Build the folded form of the word plus a map from each folded position
    // back to the index of the original character that produced it, so the
    // highlight lands on the right (accented) characters.
    let folded = "";
    const map = [];
    for (let i = 0; i < word.length; i++) {
        const f = foldChar(word[i]);
        for (let j = 0; j < f.length; j++) {
            folded += f[j];
            map.push(i);
        }
    }

    const idx = folded.indexOf(foldedQuery);
    if (idx === -1) return escapeHtml(word);

    const startOrig = map[idx];
    const endFolded = idx + foldedQuery.length;
    const endOrig = endFolded < map.length ? map[endFolded] : word.length;

    const before = escapeHtml(word.slice(0, startOrig));
    const match = escapeHtml(word.slice(startOrig, endOrig));
    const after = escapeHtml(word.slice(endOrig));
    return `${before}<mark>${match}</mark>${after}`;
}

function renderWords(words, query) {
    grid.innerHTML = words
        .map((w) => `<div class="word-item">${highlight(w, query)}</div>`)
        .join("");

    const count = words.length;
    resultCount.textContent = query
        ? `${count} of ${wordlist.length} words`
        : `${count} words total`;

    if (count === 0) {
        grid.classList.add("display-none");
        emptyState.classList.remove("display-none");
    } else {
        grid.classList.remove("display-none");
        emptyState.classList.add("display-none");
    }
}

function onSearchInput() {
    const rawQuery = searchInput.value.trim();
    const foldedQuery = foldForSearch(rawQuery);
    const filtered = foldedQuery
        ? wordlist.filter((w) => foldForSearch(w).includes(foldedQuery))
        : wordlist;
    renderWords(filtered, rawQuery);
}

// Switch the active wordlist. Clears the current search so the full new list
// is shown, then re-renders.
function applyWordlist(words) {
    wordlist = words;
    searchInput.value = "";
    if (wordlist.length === 0) {
        resultCount.textContent = "Could not find the word list (window.bipWords is missing).";
        grid.classList.add("display-none");
        emptyState.classList.remove("display-none");
    } else {
        renderWords(wordlist, "");
    }
}

// Load a language wordlist by injecting its script file. Script tags work over
// the file:// protocol (unlike fetch), which keeps the tool fully offline.
function loadLanguage(lang) {
    currentLang = lang;

    if (wordlistCache[lang]) {
        applyWordlist(wordlistCache[lang]);
        return;
    }

    resultCount.textContent = "Loading…";
    const script = document.createElement("script");
    script.src = "./bip39_" + lang + ".js";
    script.onload = function () {
        const words = window.bipWords || [];
        wordlistCache[lang] = words;
        // Only apply if this is still the language the user wants (guards
        // against fast switching between languages).
        if (currentLang === lang) applyWordlist(words);
    };
    script.onerror = function () {
        if (currentLang !== lang) return;
        resultCount.textContent = "Could not load the selected word list.";
        grid.classList.add("display-none");
        emptyState.classList.remove("display-none");
    };
    document.head.appendChild(script);
}

function onLanguageChange() {
    loadLanguage(languageSelect.value);
}

// Always start on English, regardless of any option the browser may have
// restored on reload.
if (languageSelect) languageSelect.value = "english";

if (wordlist.length === 0) {
    resultCount.textContent = "Could not find the word list (window.bipWords is missing).";
    emptyState.classList.remove("display-none");
    grid.classList.add("display-none");
} else {
    renderWords(wordlist, "");
}

// --- Theme sync with CryptoToolbox (postMessage from parent iframe) ---
window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    const data = event.data;
    if (data && data.source === 'cryptotoolbox' && data.type === 'theme' &&
        (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignored */ }
    }
});