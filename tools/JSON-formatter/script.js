const input = document.getElementById("json-input");
const output = document.getElementById("output");
const status = document.getElementById("status");
const toast = document.getElementById("toast");

function parseJSON() {
    return JSON.parse(input.value);
}

// --- JWT ---

const JWT_SEGMENT = /^[A-Za-z0-9_-]+$/;

const TIME_CLAIMS = ["iat", "nbf", "exp", "auth_time"];

// Strips quotes, the "Bearer " prefix, and line breaks from a pasted token
function cleanToken(text) {
    return text
        .trim()
        .replace(/^["']|["']$/g, "")
        .replace(/^Bearer\s+/i, "")
        .replace(/\s+/g, "");
}

// Returns the token's parts if the text looks like a JWS (3 parts) or JWE (5 parts)
function splitToken(text) {
    const parts = cleanToken(text).split(".");

    if (parts.length !== 3 && parts.length !== 5) return null;
    if (!parts[0] || !parts[1]) return null;
    if (!parts.every(p => p === "" || JWT_SEGMENT.test(p))) return null;

    return parts;
}

function base64UrlDecode(segment) {
    let base64 = segment
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    while (base64.length % 4 !== 0) {
        base64 += "=";
    }

    const binary = atob(base64);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
}

// Decodes a token part into an object, or to raw text if the content is not JSON
function decodeSegment(segment) {
    const text = base64UrlDecode(segment);

    try {
        return JSON.parse(text);
    }

    catch (e) {
        return text;
    }
}

function isObject(value) {
    return !!value && typeof value === "object";
}

function formatTime(seconds) {
    const date = new Date(seconds * 1000);

    if (isNaN(date.getTime())) return "invalid timestamp";

    return date.toLocaleString("sv-SE");
}

// Human-readable dates for timestamp claims, as a separate object in the result
function timeClaims(payload) {
    if (!isObject(payload)) return null;

    const claims = {};

    TIME_CLAIMS
        .filter(claim => typeof payload[claim] === "number")
        .forEach(claim => {
            claims[claim] = formatTime(payload[claim])
                + (claim === "exp" && isExpired(payload) ? " (expired)" : "");
        });

    return Object.keys(claims).length ? claims : null;
}

function isExpired(payload) {
    return isObject(payload)
        && typeof payload.exp === "number"
        && payload.exp * 1000 < Date.now();
}

function decodeJWT() {
    const parts = splitToken(input.value);
    if (!parts) return null;

    const header = decodeSegment(parts[0]);
    const result = { header: header };

    let payload = null;

    if (parts.length === 5) {
        result.payload = "Encrypted token (JWE) - cannot be decoded without a key";
    }

    else {
        payload = decodeSegment(parts[1]);
        result.payload = payload;
        result.signature = parts[2] || "(tom - osignerad token)";
    }

    const claims = timeClaims(payload);
    if (claims) result.timestamps = claims;

    return {
        text: JSON.stringify(result, null, 2),
        alg: isObject(header) && header.alg ? String(header.alg) : "unknown alg",
        expired: isExpired(payload)
    };
}

// Gives a clearer error line when the pasted content is a JWT and not JSON
function invalidJsonMessage() {
    return splitToken(input.value)
        ? "Invalid JSON - looks like a JWT, use Decode JWT"
        : "Invalid JSON";
}

function showToast(text) {
    toast.textContent = text;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
}

function setSuccess(text) {
    status.textContent = "✓ " + text;
    status.style.color = "var(--success)";
}

function setError(text) {
    status.textContent = "✕ " + text;
    status.style.color = "var(--error)";
}

function setWarning(text) {
    status.textContent = "⚠ " + text;
    status.style.color = "var(--error)";
}

document
    .getElementById("format-button")
    .onclick = function () {
        try {
            const json = parseJSON();
            output.textContent =
                JSON.stringify(json, null, 2);
            setSuccess("Valid JSON - formatted");
        }
        
        catch (e) {
            output.textContent = e.message;
            setError(invalidJsonMessage());
        }
    };

document
    .getElementById("minify-button")
    .onclick = function () {
        try {
            const json = parseJSON();
            output.textContent =
                JSON.stringify(json);
            setSuccess("JSON minifierad");
        }

        catch (e) {
            output.textContent = e.message;
            setError(invalidJsonMessage());
        }
    };

document
    .getElementById("jwt-button")
    .onclick = function () {
        try {
            const jwt = decodeJWT();

            if (!jwt) {
                output.textContent =
                    "No JWT found in the input.\n\n"
                    + "A JWT consists of Base64URL parts separated by dots:\n"
                    + "header.payload.signatur";
                setError("No valid JWT");
                return;
            }

            output.textContent = jwt.text;

            if (jwt.expired) {
                setWarning("JWT decoded (" + jwt.alg + ") - token has expired");
            }

            else {
                setSuccess("JWT decoded (" + jwt.alg + ") - the signature is not verified");
            }
        }

        catch (e) {
            output.textContent = e.message;
            setError("Could not decode JWT");
        }
    };

document
    .getElementById("clear-button")
    .onclick = function () {
        input.value = "";
        output.textContent = "Result appears here";
        status.textContent = "No JSON loaded";
    };

document
    .getElementById("copy-button")
    .onclick = function () {
        navigator.clipboard.writeText(
            output.textContent
        );
        showToast("JSON copied");
    };

document.addEventListener("keydown", e => {
    if (e.ctrlKey && e.key === "Enter") {
        document
            .getElementById("format-button")
            .click();
    }
});

input.addEventListener("keydown", e => {
    if (e.key === "Tab") {
        e.preventDefault();
        let start = input.selectionStart;
        let end = input.selectionEnd;
        input.value =
            input.value.substring(0, start)
            + "    "
            + input.value.substring(end);
        input.selectionStart =
            input.selectionEnd =
            start + 4;
    }
});

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