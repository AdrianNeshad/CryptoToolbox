const input = document.getElementById("json-input");
const output = document.getElementById("output");

const status = document.getElementById("status");

const toast = document.getElementById("toast");



function parseJSON() {

    return JSON.parse(input.value);

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

    status.style.color = "#3ecf8e";

}



function setError(text) {

    status.textContent = "✕ " + text;

    status.style.color = "#f0616e";

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

            setError("Ogiltig JSON");

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

            setError("Ogiltig JSON");

        }


    };






document
    .getElementById("validate-button")
    .onclick = function () {


        try {


            parseJSON();


            setSuccess("JSON är giltig");


        }

        catch (e) {

            setError("JSON är ogiltig");


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






// Ctrl + Enter formattera

document.addEventListener("keydown", e => {


    if (e.ctrlKey && e.key === "Enter") {

        document
            .getElementById("format-button")
            .click();

    }


});



// Tab fungerar i textarea

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