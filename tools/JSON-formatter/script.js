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

// Plockar bort citattecken, "Bearer "-prefix och radbrytningar från inklistrad token
function cleanToken(text) {
    return text
        .trim()
        .replace(/^["']|["']$/g, "")
        .replace(/^Bearer\s+/i, "")
        .replace(/\s+/g, "");
}

// Returnerar tokens delar om texten ser ut som en JWS (3 delar) eller JWE (5 delar)
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

// Avkodar en del av token till ett objekt, eller till råtext om innehållet inte är JSON
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

    if (isNaN(date.getTime())) return "ogiltig tidsstämpel";

    return date.toLocaleString("sv-SE");
}

// Läsbara datum för tidsstämpel-claims, som ett eget objekt i resultatet
function timeClaims(payload) {
    if (!isObject(payload)) return null;

    const claims = {};

    TIME_CLAIMS
        .filter(claim => typeof payload[claim] === "number")
        .forEach(claim => {
            claims[claim] = formatTime(payload[claim])
                + (claim === "exp" && isExpired(payload) ? " (utgången)" : "");
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
        result.payload = "Krypterad token (JWE) - kan inte avkodas utan nyckel";
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
        alg: isObject(header) && header.alg ? String(header.alg) : "okänd alg",
        expired: isExpired(payload)
    };
}

// Ger en tydligare felrad när det som klistrats in är en JWT och inte JSON
function invalidJsonMessage() {
    return splitToken(input.value)
        ? "Ogiltig JSON - ser ut som en JWT, använd Decode JWT"
        : "Ogiltig JSON";
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
            setSuccess("Giltig JSON - formatterad");
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
                    "Ingen JWT hittades i inmatningen.\n\n"
                    + "En JWT består av Base64URL-delar separerade med punkter:\n"
                    + "header.payload.signatur";
                setError("Ingen giltig JWT");
                return;
            }

            output.textContent = jwt.text;

            if (jwt.expired) {
                setWarning("JWT avkodad (" + jwt.alg + ") - token har gått ut");
            }

            else {
                setSuccess("JWT avkodad (" + jwt.alg + ") - signaturen verifieras inte");
            }
        }

        catch (e) {
            output.textContent = e.message;
            setError("Kunde inte avkoda JWT");
        }
    };

document
    .getElementById("clear-button")
    .onclick = function () {
        input.value = "";
        output.textContent = "Resultat visas här";
        status.textContent = "Ingen JSON laddad";
    };

document
    .getElementById("copy-button")
    .onclick = function () {
        navigator.clipboard.writeText(
            output.textContent
        );
        showToast("JSON kopierad");
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