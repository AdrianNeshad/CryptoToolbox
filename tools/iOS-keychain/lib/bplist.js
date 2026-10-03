// Minimal binary property-list (bplist00) parser.
//
// Used for Manifest.plist, the NSKeyedArchiver blobs inside Manifest.db, and the
// decrypted keychain-backup.plist. Only the object types that appear in those
// files are handled. UIDs are returned as KC.bplist.UID so the NSKeyedArchiver
// layer (nskeyed.js) can resolve object references.
(function () {
  'use strict';

  function UID(v) { this.value = v; }

  function readUInt(view, off, len) {
    // big-endian unsigned; uses Number (safe for the sizes in these files).
    var v = 0;
    for (var i = 0; i < len; i++) v = v * 256 + view.getUint8(off + i);
    return v;
  }

  function parse(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    if (bytes.length < 40) throw new Error('bplist: too short');
    var magic = String.fromCharCode.apply(null, bytes.subarray(0, 6));
    if (magic !== 'bplist') throw new Error('bplist: bad magic');
    var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    var trailerOff = bytes.length - 32;
    var offsetSize = view.getUint8(trailerOff + 6);
    var refSize = view.getUint8(trailerOff + 7);
    var numObjects = readUInt(view, trailerOff + 8, 8);
    var topObject = readUInt(view, trailerOff + 16, 8);
    var offTableOff = readUInt(view, trailerOff + 24, 8);

    var offsets = new Array(numObjects);
    for (var i = 0; i < numObjects; i++) {
      offsets[i] = readUInt(view, offTableOff + i * offsetSize, offsetSize);
    }

    var cache = new Array(numObjects);

    function readRef(off) { return readUInt(view, off, refSize); }

    function readSized(off) {
      // returns {count, dataOff}
      var marker = view.getUint8(off);
      var info = marker & 0x0f;
      var count = info;
      var p = off + 1;
      if (info === 0x0f) {
        var im = view.getUint8(p);
        var ilen = 1 << (im & 0x0f);
        p += 1;
        count = readUInt(view, p, ilen);
        p += ilen;
      }
      return { count: count, dataOff: p };
    }

    function readObject(index) {
      if (cache[index] !== undefined) return cache[index];
      var off = offsets[index];
      var marker = view.getUint8(off);
      var type = marker & 0xf0;
      var info = marker & 0x0f;
      var val;

      switch (type) {
        case 0x00:
          if (marker === 0x00) val = null;
          else if (marker === 0x08) val = false;
          else if (marker === 0x09) val = true;
          else if (marker === 0x0f) val = null; // fill
          else val = null;
          break;
        case 0x10: { // int
          var ilen = 1 << info;
          if (ilen <= 4) val = readUInt(view, off + 1, ilen);
          else if (ilen === 8) {
            // signed 64-bit
            var hi = view.getInt32(off + 1), lo = view.getUint32(off + 5);
            val = hi * 4294967296 + lo;
          } else {
            val = readUInt(view, off + 1 + (ilen - 8), 8); // 16-byte: low 64 bits
          }
          break;
        }
        case 0x20: // real
          val = info === 3 ? view.getFloat64(off + 1) : view.getFloat32(off + 1);
          break;
        case 0x30: // date (seconds since 2001-01-01)
          val = { __nsdate: view.getFloat64(off + 1) };
          break;
        case 0x40: { // data
          var d = readSized(off);
          val = bytes.slice(d.dataOff, d.dataOff + d.count);
          break;
        }
        case 0x50: { // ASCII string
          var s = readSized(off);
          val = String.fromCharCode.apply(null, bytes.subarray(s.dataOff, s.dataOff + s.count));
          break;
        }
        case 0x60: { // UTF-16BE string
          var u = readSized(off);
          var str = '';
          for (var c = 0; c < u.count; c++) str += String.fromCharCode(view.getUint16(u.dataOff + c * 2));
          val = str;
          break;
        }
        case 0x80: // UID
          val = new UID(readUInt(view, off + 1, info + 1));
          break;
        case 0xa0:   // array
        case 0xc0: { // set
          var a = readSized(off);
          var arr = new Array(a.count);
          for (var k = 0; k < a.count; k++) arr[k] = readObject(readRef(a.dataOff + k * refSize));
          val = arr;
          break;
        }
        case 0xd0: { // dict
          var dd = readSized(off);
          var obj = {};
          var keysOff = dd.dataOff;
          var valsOff = dd.dataOff + dd.count * refSize;
          for (var m = 0; m < dd.count; m++) {
            var key = readObject(readRef(keysOff + m * refSize));
            var value = readObject(readRef(valsOff + m * refSize));
            obj[String(key)] = value;
          }
          val = obj;
          break;
        }
        default:
          throw new Error('bplist: unsupported marker 0x' + marker.toString(16));
      }
      cache[index] = val;
      return val;
    }

    return readObject(topObject);
  }

  window.KC = window.KC || {};
  window.KC.bplist = { parse: parse, UID: UID };
})();
