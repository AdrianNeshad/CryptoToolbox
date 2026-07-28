// Bech32 (BIP-173) / Bech32m (BIP-350) encoding for native SegWit addresses.
// Witness version 0 (bc1q...) uses the original bech32 checksum constant (1),
// witness version 1+ (bc1p... / taproot) uses the bech32m constant (0x2bc830a3).
(function () {
    var CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    function polymod(values) {
        var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        var chk = 1;
        for (var p = 0; p < values.length; p++) {
            var top = chk >>> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ values[p];
            for (var i = 0; i < 5; i++) {
                if ((top >>> i) & 1) chk ^= GEN[i];
            }
        }
        return chk >>> 0;
    }

    function hrpExpand(hrp) {
        var ret = [];
        var p;
        for (p = 0; p < hrp.length; p++) ret.push(hrp.charCodeAt(p) >>> 5);
        ret.push(0);
        for (p = 0; p < hrp.length; p++) ret.push(hrp.charCodeAt(p) & 31);
        return ret;
    }

    function createChecksum(hrp, data, constant) {
        var values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
        var mod = polymod(values) ^ constant;
        var ret = [];
        for (var p = 0; p < 6; p++) ret.push((mod >>> (5 * (5 - p))) & 31);
        return ret;
    }

    function encode(hrp, data, constant) {
        var combined = data.concat(createChecksum(hrp, data, constant));
        var ret = hrp + "1";
        for (var p = 0; p < combined.length; p++) ret += CHARSET.charAt(combined[p]);
        return ret;
    }

    function convertBits(data, fromBits, toBits, pad) {
        var acc = 0, bits = 0, ret = [];
        var maxv = (1 << toBits) - 1;
        for (var i = 0; i < data.length; i++) {
            acc = (acc << fromBits) | data[i];
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.push((acc >>> bits) & maxv);
            }
        }
        if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
        return ret;
    }

    // program: Buffer/Array of bytes (witness program), version: 0-16
    function encodeSegwitAddress(hrp, version, program) {
        var bytes = Array.prototype.slice.call(program);
        var data = [version].concat(convertBits(bytes, 8, 5, true));
        var constant = version === 0 ? 1 : 0x2bc830a3;
        return encode(hrp, data, constant);
    }

    window.encodeSegwitAddress = encodeSegwitAddress;
})();
