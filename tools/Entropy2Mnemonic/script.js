const row = document.getElementById("entropy-row");
const validation = document.getElementById("validation");
const output = document.getElementById("output");
const toast = document.getElementById("toast");
const checksumStatus = document.getElementById("checksum-status");

let FIELD_COUNT = 16;

let renderToken = 0;

function bytesToBinary(bytes) {
    return bytes.map(b => b.toString(2).padStart(8, "0")).join("");
}

async function sha256(bytes) {
    const hash = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
    return Array.from(new Uint8Array(hash));
}

async function entropyToMnemonic(entropyBytes, wordlist) {
    const hash = await sha256(entropyBytes);

    const entropyBits = bytesToBinary(entropyBytes);
    const checksumBits = bytesToBinary(hash).slice(0, entropyBytes.length / 4);

    const bits = entropyBits + checksumBits;

    const words = [];
    for (let i = 0; i < bits.length / 11; i++) {
        const chunk = bits.slice(i * 11, (i + 1) * 11);
        const index = parseInt(chunk, 2);
        words.push(wordlist[index]);
    }

    return words;
}

function binaryToBytes(bits) {
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return bytes;
}

// Independently decodes the generated words back into bits and recomputes
// the SHA-256 checksum from the entropy portion, so the checksum embedded
// in the last word(s) can be verified rather than just trusted.
async function verifyChecksum(words, wordlist) {
    const bits = words
        .map(word => wordlist.indexOf(word).toString(2).padStart(11, "0"))
        .join("");

    const totalBits = bits.length;
    const checksumBitLength = totalBits / 33;
    const entropyBitLength = totalBits - checksumBitLength;

    const entropyBits = bits.slice(0, entropyBitLength);
    const embeddedChecksumBits = bits.slice(entropyBitLength);

    const entropyBytes = binaryToBytes(entropyBits);
    const hash = await sha256(entropyBytes);
    const recomputedChecksumBits = bytesToBinary(hash).slice(0, checksumBitLength);

    return {
        valid: recomputedChecksumBits === embeddedChecksumBits,
        checksumBitLength,
    };
}

function createField(index) {
    const wrapper = document.createElement("div");
    wrapper.className = "entropy-field";

    const input = document.createElement("input");
    input.type = "text";
    input.inputMode = "numeric";
    input.pattern = "[0-9]*";
    input.maxLength = 3;
    input.autocomplete = "off";
    input.spellcheck = false;
    input.placeholder = String(index + 1);
    input.addEventListener("input", onFieldInput);
    input.addEventListener("keydown", onFieldKeydown);

    wrapper.appendChild(input);
    return wrapper;
}

function addField(index) {
    row.appendChild(createField(index));
}

function setFieldCount(count) {
    const existingValues = getFieldInputs().map(input => input.value);

    FIELD_COUNT = count;
    row.innerHTML = "";
    for (let i = 0; i < FIELD_COUNT; i++) addField(i);

    const inputs = getFieldInputs();
    inputs.forEach((input, i) => {
        if (existingValues[i] !== undefined) input.value = existingValues[i];
    });

    onFieldsChanged();
}

function getFieldInputs() {
    return Array.from(row.querySelectorAll("input"));
}

function onFieldInput(event) {
    const input = event.target;
    const digitsOnly = input.value.replace(/\D/g, "").slice(0, 3);
    input.value = digitsOnly;

    if (digitsOnly.length === 3) {
        const inputs = getFieldInputs();
        const next = inputs[inputs.indexOf(input) + 1];
        if (next) next.focus();
    }

    onFieldsChanged();
}

function onFieldKeydown(event) {
    const input = event.target;
    const inputs = getFieldInputs();
    const index = inputs.indexOf(input);
    const atStart = input.selectionStart === 0 && input.selectionEnd === 0;
    const atEnd = input.selectionStart === input.value.length && input.selectionEnd === input.value.length;

    if (event.key === "ArrowLeft" && atStart) {
        const prev = inputs[index - 1];
        if (prev) {
            event.preventDefault();
            prev.focus();
            const pos = prev.value.length;
            prev.setSelectionRange(pos, pos);
        }
    } else if (event.key === "ArrowRight" && atEnd) {
        const next = inputs[index + 1];
        if (next) {
            event.preventDefault();
            next.focus();
            next.setSelectionRange(0, 0);
        }
    }
}

function resetValidation() {
    validation.textContent = "";
    validation.classList.add("display-none");
}

function showValidation(text) {
    validation.textContent = "❌ " + text;
    validation.classList.remove("display-none");
}

function hideChecksumStatus() {
    checksumStatus.textContent = "";
    checksumStatus.classList.add("display-none");
    checksumStatus.classList.remove("valid", "invalid");
}

function showChecksumStatus(valid, checksumBitLength) {
    checksumStatus.classList.remove("display-none");
    checksumStatus.classList.toggle("valid", valid);
    checksumStatus.classList.toggle("invalid", !valid);
    checksumStatus.textContent = valid
        ? `✓ Giltig checksum (${checksumBitLength} bitar kontrollerade)`
        : `✗ Ogiltig checksum (${checksumBitLength} bitar kontrollerade)`;
}

function onFieldsChanged() {
    resetValidation();
    hideChecksumStatus();

    const inputs = getFieldInputs();
    const bytes = [];
    let hasInvalidByte = false;
    let hasEmptyField = false;

    for (const input of inputs) {
        const raw = input.value.trim();

        if (raw === "") {
            input.classList.remove("invalid");
            hasEmptyField = true;
            continue;
        }

        const num = Number(raw);
        const isValidByte = Number.isInteger(num) && num >= 0 && num <= 255;

        input.classList.toggle("invalid", !isValidByte);
        if (!isValidByte) hasInvalidByte = true;
        else bytes.push(num);
    }

    if (hasInvalidByte) {
        showValidation("Varje fält måste vara ett heltal mellan 0 och 255.");
        output.textContent = "Mnemonic-frasen visas här";
        return;
    }

    if (hasEmptyField) {
        showValidation("Fyll i ett värde (0–255) i alla fält.");
        output.textContent = "Mnemonic-frasen visas här";
        return;
    }

    generateMnemonic(bytes);
}

async function generateMnemonic(bytes) {
    const token = ++renderToken;
    try {
        const wordlist = window.entropyWordlists.bip39;
        const words = await entropyToMnemonic(bytes, wordlist);
        const checksum = await verifyChecksum(words, wordlist);
        if (token !== renderToken) return;

        output.textContent = words.join(" ");
        showChecksumStatus(checksum.valid, checksum.checksumBitLength);
    } catch (e) {
        if (token !== renderToken) return;
        showValidation(e.message);
        output.textContent = "Mnemonic-frasen visas här";
        hideChecksumStatus();
    }
}

function showToast(text) {
    toast.textContent = text;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
}

document.getElementById("copy-button").addEventListener("click", () => {
    navigator.clipboard.writeText(output.textContent);
    showToast("Mnemonic kopierad");
});

document.getElementById("word-count-toggle").addEventListener("click", (event) => {
    const btn = event.target.closest(".toggle-btn");
    if (!btn || btn.classList.contains("active")) return;

    document.querySelectorAll("#word-count-toggle .toggle-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");

    const wordCount = Number(btn.dataset.words);
    setFieldCount(wordCount === 24 ? 32 : 16);
});

setFieldCount(FIELD_COUNT);

// --- Temasynkronisering med Verktygslådan (postMessage från förälder-iframe) ---
window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    var data = event.data;
    if (data && data.source === 'verktygslada' && data.type === 'theme' &&
        (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignoreras */ }
    }
});
