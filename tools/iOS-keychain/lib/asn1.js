// Tiny DER / ASN.1 reader for decrypted keychain records.
//
// Each decrypted keychain item is a DER container (SET/SEQUENCE) of two-element
// {key, value} pairs, matching the structure irestore parses with encoding/asn1.
(function () {
  'use strict';

  function readTLV(bytes, pos) {
    var tag = bytes[pos];
    var cls = tag & 0xc0;
    var constructed = (tag & 0x20) !== 0;
    var tagNum = tag & 0x1f;
    var p = pos + 1;
    // long-form tag numbers (rare here) -- consume continuation bytes
    if (tagNum === 0x1f) { while (bytes[p] & 0x80) p++; p++; }
    var len = bytes[p++];
    if (len & 0x80) {
      var n = len & 0x7f;
      len = 0;
      for (var i = 0; i < n; i++) len = len * 256 + bytes[p++];
    }
    var contentStart = p;
    var contentEnd = p + len;
    return {
      tag: tag, cls: cls, constructed: constructed, tagNum: tagNum,
      contentStart: contentStart, contentEnd: contentEnd, next: contentEnd
    };
  }

  function children(bytes, node) {
    var out = [];
    var p = node.contentStart;
    while (p < node.contentEnd) {
      var t = readTLV(bytes, p);
      out.push(t);
      p = t.next;
    }
    return out;
  }

  function decodeString(bytes, node) {
    return utf8(bytes.subarray(node.contentStart, node.contentEnd));
  }

  function utf8(u) {
    try { return new TextDecoder('utf-8', { fatal: false }).decode(u); }
    catch (e) { return String.fromCharCode.apply(null, u); }
  }

  function decodeInteger(bytes, node) {
    var len = node.contentEnd - node.contentStart;
    if (len <= 6) {
      var v = 0, neg = bytes[node.contentStart] & 0x80;
      for (var i = node.contentStart; i < node.contentEnd; i++) v = v * 256 + bytes[i];
      if (neg) v -= Math.pow(2, 8 * len);
      return v;
    }
    return bytes.slice(node.contentStart, node.contentEnd); // big: keep bytes
  }

  // Decode an ASN.1 value node into a JS value.
  function decodeValue(bytes, node) {
    if (node.cls !== 0x00) { // context/application: keep raw
      return bytes.slice(node.contentStart, node.contentEnd);
    }
    switch (node.tagNum) {
      case 0x01: // BOOLEAN
        return bytes[node.contentStart] !== 0;
      case 0x02: // INTEGER
        return decodeInteger(bytes, node);
      case 0x03: // BIT STRING
        return bytes.slice(node.contentStart, node.contentEnd);
      case 0x04: // OCTET STRING
        return bytes.slice(node.contentStart, node.contentEnd);
      case 0x05: // NULL
        return null;
      case 0x0c: // UTF8String
      case 0x12: // NumericString
      case 0x13: // PrintableString
      case 0x16: // IA5String
      case 0x14: // TeletexString
        return decodeString(bytes, node);
      case 0x17: // UTCTime
      case 0x18: // GeneralizedTime
        return { __asn1time: decodeString(bytes, node) };
      default:
        if (node.constructed) {
          return children(bytes, node).map(function (c) { return decodeValue(bytes, c); });
        }
        return bytes.slice(node.contentStart, node.contentEnd);
    }
  }

  // Parse a keychain record blob into { key: value, ... }.
  function parseRecord(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    var rec = {};
    if (bytes.length === 0) return rec;
    var top = readTLV(bytes, 0);
    var pairs = children(bytes, top);
    for (var i = 0; i < pairs.length; i++) {
      var pair = pairs[i];
      if (!pair.constructed) continue;
      var kv = children(bytes, pair);
      if (kv.length < 2) continue;
      var key = decodeString(bytes, kv[0]);
      rec[key] = decodeValue(bytes, kv[1]);
    }
    return rec;
  }

  window.KC = window.KC || {};
  window.KC.asn1 = { parseRecord: parseRecord, readTLV: readTLV, children: children, decodeValue: decodeValue };
})();
