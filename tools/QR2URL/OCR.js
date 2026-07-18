document.addEventListener("DOMContentLoaded", () => {
    const ocrResultDiv = document.getElementById("ocr-result");
    const ocrCopyButton = document.getElementById("ocr-copy-button");
    const toast = document.getElementById("toast");

    function runOcr(imageDataUrl) {
        displayOcrResult("Läser av text (OCR)...", false);

        Tesseract.recognize(imageDataUrl, "eng+swe", {
            workerPath: "./tesseract/worker.min.js",
            corePath: "./tesseract/tesseract-core.wasm.js",
            langPath: "./tesseract", // eng.traineddata.gz / swe.traineddata.gz letas upp här
            gzip: true,
        })
            .then(({ data: { text } }) => {
                const cleaned = text.trim();
                displayOcrResult(cleaned || "Ingen text hittades.", !cleaned);
            })
            .catch((error) => {
                displayOcrResult("Fel vid OCR-avläsning.", true);
                console.error("OCR error:", error);
            });
    }

    function displayOcrResult(text, isError) {
        ocrResultDiv.innerHTML = "";
        const p = document.createElement("p");
        p.textContent = text;
        if (isError) {
            p.classList.add("error");
        }
        ocrResultDiv.appendChild(p);
    }

    function showOcrToast(message) {
        toast.textContent = message;
        toast.classList.add("show");
        setTimeout(() => {
            toast.classList.remove("show");
        }, 3000);
    }

    ocrCopyButton.addEventListener("click", () => {
        const ocrText = ocrResultDiv.innerText;
        if (ocrText) {
            navigator.clipboard
                .writeText(ocrText)
                .then(() => showOcrToast("OCR-text kopierad!"))
                .catch((err) => console.error("Failed to copy text: ", err));
        }
    });

    ocrResultDiv.addEventListener("dblclick", () => {
        const ocrText = ocrResultDiv.innerText.trim();
        if (!ocrText) return;

        navigator.clipboard
            .writeText(ocrText)
            .then(() => {
                ocrResultDiv.classList.add("copied");
                setTimeout(() => ocrResultDiv.classList.remove("copied"), 800);
                showOcrToast("OCR-text kopierad!");
            })
            .catch((err) => console.error("Failed to copy text: ", err));
    });

    // Exponera funktionen globalt så script.js kan anropa den
    window.runOcr = runOcr;
    window.displayOcrResult = displayOcrResult;
});