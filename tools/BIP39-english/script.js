// Denna fil förväntar sig en global array `window.bipWords` från bip39_english.js

const grid = document.getElementById("word-grid");
const emptyState = document.getElementById("empty-state");
const resultCount = document.getElementById("result-count");
const searchInput = document.getElementById("search-input");

const wordlist = window.bipWords || [];

function escapeHtml(str) {
    return str.replace(/[&<>"']/g, (c) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
    }[c]));
}

function highlight(word, query) {
    if (!query) return escapeHtml(word);
    const idx = word.toLowerCase().indexOf(query.toLowerCase());
    if (idx === -1) return escapeHtml(word);
    const before = escapeHtml(word.slice(0, idx));
    const match = escapeHtml(word.slice(idx, idx + query.length));
    const after = escapeHtml(word.slice(idx + query.length));
    return `${before}<mark>${match}</mark>${after}`;
}

function renderWords(words, query) {
    grid.innerHTML = words
        .map((w) => `<div class="word-item">${highlight(w, query)}</div>`)
        .join("");

    const count = words.length;
    resultCount.textContent = query
        ? `${count} av ${wordlist.length} ord`
        : `${count} ord totalt`;

    if (count === 0) {
        grid.classList.add("display-none");
        emptyState.classList.remove("display-none");
    } else {
        grid.classList.remove("display-none");
        emptyState.classList.add("display-none");
    }
}

function onSearchInput() {
    const query = searchInput.value.trim().toLowerCase();
    const filtered = query
        ? wordlist.filter((w) => w.toLowerCase().includes(query))
        : wordlist;
    renderWords(filtered, query);
}

if (wordlist.length === 0) {
    resultCount.textContent = "Kunde inte hitta ordlistan (window.bipWords saknas).";
    emptyState.classList.remove("display-none");
    grid.classList.add("display-none");
} else {
    renderWords(wordlist, "");
}