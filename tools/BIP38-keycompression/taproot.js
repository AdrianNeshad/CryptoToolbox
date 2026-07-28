// BIP-341 taproot output key derivation (key-path only, no script tree),
// using the secp256k1 curve implementation already bundled with bitcoinjs.
(function () {
    var curve = bitcoinjs.ecurve.getCurveByName("secp256k1");
    var BigInteger = bitcoinjs.BigInteger;
    var bcrypto = bitcoinjs.bitcoin.crypto;
    var NodeBuffer = bitcoinjs.Buffer.Buffer;

    function taggedHash(tag, msg) {
        var tagHash = bcrypto.sha256(NodeBuffer.from(tag, "utf8"));
        return bcrypto.sha256(NodeBuffer.concat([tagHash, tagHash, msg]));
    }

    // BIP-340 lift_x: the point on the curve with the given x-coordinate and an even y.
    function liftX(xBuffer) {
        var x = BigInteger.fromBuffer(xBuffer);
        if (x.compareTo(curve.p) >= 0) return null;
        return curve.pointFromX(false, x);
    }

    // compressedPubkeyBuffer: 33-byte SEC1 compressed public key.
    // Returns the 32-byte x-only taproot output key, or null if the x
    // coordinate isn't valid on the curve (astronomically unlikely).
    function getTaprootOutputKey(compressedPubkeyBuffer) {
        var xOnly = compressedPubkeyBuffer.slice(1, 33);
        var internalPoint = liftX(xOnly);
        if (!internalPoint) return null;

        var tweak = BigInteger.fromBuffer(taggedHash("TapTweak", xOnly));
        var outputPoint = internalPoint.add(curve.G.multiply(tweak));
        return outputPoint.affineX.toBuffer(32);
    }

    window.getTaprootOutputKey = getTaprootOutputKey;
})();
