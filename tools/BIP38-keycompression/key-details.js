KeyDetails = function (parentEl, displayCompressed) {

    var self = this;

    var template = $("#key-details").html();
    var el = $(template);
    parentEl.append(el);

    var DOM = {};
    DOM.address = el.find(".address");
    DOM.pubkey = el.find(".public-key");
    DOM.privkey = el.find(".private-key");
    DOM.bip38privkey = el.find(".bip38-private-key");
    DOM.bip38password = $(".supplied-password");

    // Native SegWit (bc1q) and Taproot (bc1p) addresses always use the
    // compressed public key encoding, so only show them next to the
    // compressed key details.
    if (displayCompressed) {
        var segwitGroup = $(
            '<div class="form-group">' +
            '<label class="form-label">Address (SegWit, bc1q)</label>' +
            '<input class="segwit-address form-control" readonly>' +
            '</div>'
        );
        var taprootGroup = $(
            '<div class="form-group">' +
            '<label class="form-label">Address (Taproot, bc1p)</label>' +
            '<input class="taproot-address form-control" readonly>' +
            '</div>'
        );
        var addressGroup = DOM.address.closest(".form-group");
        addressGroup.after(taprootGroup);
        addressGroup.after(segwitGroup);
        DOM.segwitAddress = segwitGroup.find(".segwit-address");
        DOM.taprootAddress = taprootGroup.find(".taproot-address");
    }

    this.setPrivateKey = function (originalKey) {
        var o = { compressed: displayCompressed };
        var displayKey = new bitcoinjs.bitcoin.ECPair(originalKey.d, null, o);
        display(displayKey);
    }

    this.setPublicKey = function (originalKey) {
        var o = { compressed: displayCompressed };
        var displayKey = new bitcoinjs.bitcoin.ECPair(null, originalKey.__Q, o);
        display(displayKey);
    }

    function display(displayKey) {
        self.clear()
        // show address
        DOM.address.val(displayKey.getAddress());
        // show public key hex
        var pubkeyBuffer = displayKey.getPublicKeyBuffer();
        DOM.pubkey.val(pubkeyBuffer.toString("hex"));
        // show native SegWit / Taproot addresses derived from the compressed pubkey
        if (displayCompressed) {
            var hash160 = bitcoinjs.bitcoin.crypto.hash160(pubkeyBuffer);
            DOM.segwitAddress.val(encodeSegwitAddress("bc", 0, hash160));
            var taprootOutputKey = getTaprootOutputKey(pubkeyBuffer);
            if (taprootOutputKey) {
                DOM.taprootAddress.val(encodeSegwitAddress("bc", 1, taprootOutputKey));
            }
        }
        // if it has private key details
        if (displayKey.d) {
            // show private key wif
            DOM.privkey.val(displayKey.toWIF());
            // show BIP38 key
            var bip38password = DOM.bip38password.val();
            if (bip38password != "") {
                var bip38privkey = bitcoinjsBip38.encrypt(displayKey.d.toBuffer(), displayKey.compressed, bip38password);
                DOM.bip38privkey.val(bip38privkey);
            }
        }
    }

    this.clear = function () {
        DOM.address.val("");
        DOM.pubkey.val("");
        DOM.privkey.val("");
        DOM.bip38privkey.val("");
        if (displayCompressed) {
            DOM.segwitAddress.val("");
            DOM.taprootAddress.val("");
        }
    }
}