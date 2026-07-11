document.addEventListener("DOMContentLoaded", () => {
    const dropArea = document.getElementById("drop-area");
    const fileInput = document.getElementById("file-input");
    const qrcodeResultDiv = document.getElementById("qrcode-result");
    const cameraButton = document.getElementById("camera-button");
    const cameraStreamElement = document.getElementById("camera-stream");
    let cameraActive = false;
    let videoStream = null;

    // Prevent default drag behaviors
    ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Highlight drop area when item is dragged over it
    ["dragenter", "dragover"].forEach((eventName) => {
        dropArea.addEventListener(eventName, highlight, false);
    });

    ["dragleave", "drop"].forEach((eventName) => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });

    function highlight(e) {
        dropArea.classList.add("highlight");
    }

    function unhighlight(e) {
        dropArea.classList.remove("highlight");
    }

    // Handle dropped files
    dropArea.addEventListener("drop", handleDrop, false);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        handleFiles(files);
    }

    // Click to open file dialog
    dropArea.addEventListener("click", (e) => {
        if (e.target !== cameraButton) {
            // Prevent file dialog opening when clicking camera button
            fileInput.click();
        }
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

    cameraButton.addEventListener("click", () => {
        if (!cameraActive) {
            startCamera();
        } else {
            stopCamera();
        }
    });

    function startCamera() {
        navigator.mediaDevices
            .getUserMedia({ video: { facingMode: "environment" } }) // Use 'environment' for back camera if available
            .then((stream) => {
                videoStream = stream;
                cameraStreamElement.srcObject = stream;
                cameraStreamElement.style.display = "block"; // Show video element
                cameraStreamElement.play();
                cameraActive = true;
                cameraButton.textContent = "Stop Camera";
                displayResult("Scanning from camera...", false);
                requestAnimationFrame(captureAndDecode);
            })
            .catch((err) => {
                console.error("Camera access error:", err);
                displayResult("Error accessing camera.", true);
            });
    }

    function stopCamera() {
        if (videoStream) {
            videoStream.getTracks().forEach((track) => track.stop());
        }
        cameraStreamElement.pause();
        cameraStreamElement.srcObject = null;
        cameraStreamElement.style.display = "none"; // Hide video element
        cameraActive = false;
        cameraButton.textContent = "Scan from Camera";
        displayResult("Camera stopped.", false);
    }

    function handleFiles(files) {
        stopCamera(); // Stop camera if active when new file is handled
        if (files.length > 0) {
            const file = files[0];
            if (
                file.type.startsWith("image/png") ||
                file.type.startsWith("image/jpeg")
            ) {
                decodeImage(file);
            } else {
                displayResult("Please upload or paste a PNG or JPG image.", true);
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

    function captureAndDecode() {
        if (!cameraActive) return; // Stop if camera is no longer active

        const canvas = document.createElement("canvas");
        canvas.width = cameraStreamElement.videoWidth;
        canvas.height = cameraStreamElement.videoHeight;
        const context = canvas.getContext("2d");
        context.drawImage(cameraStreamElement, 0, 0, canvas.width, canvas.height);
        const imageData = context.getImageData(0, 0, canvas.width, canvas.height);

        decodeQrCodeFromImageData(imageData, canvas.width, canvas.height)
            .then((decodedText) => {
                if (decodedText) {
                    displayResult(decodedText, false);
                    stopCamera(); // Stop camera after successful decode
                } else {
                    // Continue scanning if no QR code found in this frame
                    requestAnimationFrame(captureAndDecode);
                }
            })
            .catch((error) => {
                displayResult("Error decoding QR code from camera.", true);
                console.error("QR Code decoding error from camera:", error);
                stopCamera(); // Stop camera on error
            });
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