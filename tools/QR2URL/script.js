document.addEventListener("DOMContentLoaded", () => {
    const dropArea = document.getElementById("drop-area");
    const dropAreaText = document.getElementById("drop-area-text");
    const fileInput = document.getElementById("file-input");
    const qrcodeResultDiv = document.getElementById("qrcode-result");
    const previewImage = document.getElementById("preview-image");

    ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ["dragenter", "dragover"].forEach((eventName) => {
        document.body.addEventListener(eventName, highlight, false);
    });

    ["dragleave", "drop"].forEach((eventName) => {
        document.body.addEventListener(eventName, unhighlight, false);
    });

    function highlight(e) {
        dropArea.classList.add("highlight");
    }

    function unhighlight(e) {
        dropArea.classList.remove("highlight");
    }

    // Handle dropped files — now on the whole document
    document.body.addEventListener("drop", handleDrop, false);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        handleFiles(files);
    }

    // Click to open file dialog — stays scoped to drop-area only
    dropArea.addEventListener("click", () => {
        fileInput.click();
    });

    fileInput.addEventListener("change", () => {
        handleFiles(fileInput.files);
    });

    // Handle paste event
    document.addEventListener("paste", handlePaste);

    function handlePaste(event) {
        const items = (event.clipboardData || event.clipboard).items;
        let imageFile = null;
        for (let i = 0; i < items.length; i++) {
            if (items[i].type.indexOf("image") === 0) {
                imageFile = items[i].getAsFile();
                break; // Take the first image if multiple
            }
        }
        if (imageFile) {
            handleFiles([imageFile]); // Handle pasted image as a file
        }
    }

    function handleFiles(files) {
        if (files.length > 0) {
            const file = files[0];
            if (
                file.type.startsWith("image/png") ||
                file.type.startsWith("image/jpeg") ||
                file.type.startsWith("image/webp")
            ) {
                decodeImage(file);
            } else {
                displayResult("Please upload or paste a PNG, JPG or WEBP image.", true);
            }
        }
    }

    function decodeImage(imageFile) {
        displayResult("Decoding QR Code...", false);

        const reader = new FileReader();

        reader.onload = function (event) {
            const img = new Image();
            img.onload = function () {
                const canvas = document.createElement("canvas");
                canvas.width = img.width;
                canvas.height = img.height;
                const context = canvas.getContext("2d");
                context.drawImage(img, 0, 0);
                const imageData = context.getImageData(
                    0,
                    0,
                    canvas.width,
                    canvas.height
                );

                // Show the image as a preview in the drop area
                previewImage.src = event.target.result;
                previewImage.style.display = "block";
                dropAreaText.style.display = "none";

                decodeQrCodeFromImageData(imageData, canvas.width, canvas.height)
                    .then((decodedText) => {
                        displayResult(decodedText || "No QR code found.", !decodedText);
                    })
                    .catch((error) => {
                        displayResult("Error decoding QR code.", true);
                        console.error("QR Code decoding error:", error);
                    });
            };
            img.onerror = function () {
                displayResult("Error loading image.", true);
            };
            img.src = event.target.result;
        };

        reader.onerror = function () {
            displayResult("Error reading file.", true);
        };

        reader.readAsDataURL(imageFile);
    }

    function decodeQrCodeFromImageData(imageData, width, height) {
        return new Promise((resolve, reject) => {
            try {
                const code = jsQR(imageData.data, width, height);
                if (code) {
                    resolve(code.data);
                } else {
                    resolve(null); // No QR code found
                }
            } catch (error) {
                reject(error);
            }
        });
    }

    function displayResult(text, isError) {
        qrcodeResultDiv.innerHTML = ""; // Clear previous result
        const p = document.createElement("p");
        p.textContent = text;
        if (isError) {
            p.classList.add("error");
        }
        qrcodeResultDiv.appendChild(p);
    }

    const copyButton = document.getElementById("copy-button");
    const toast = document.getElementById("toast");

    copyButton.addEventListener("click", () => {
        const qrCodeText = qrcodeResultDiv.innerText;
        if (qrCodeText) {
            navigator.clipboard
                .writeText(qrCodeText)
                .then(() => {
                    showToast("Copied to clipboard!");
                })
                .catch((err) => {
                    console.error("Failed to copy text: ", err);
                });
        }
    });

    function showToast(message) {
        toast.textContent = message;
        toast.classList.add("show");
        setTimeout(() => {
            toast.classList.remove("show");
        }, 3000);
    }
});