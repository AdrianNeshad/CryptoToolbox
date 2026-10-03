// NSKeyedArchiver deserializer, ported from dunhamsteve/ios kvarchive.
//
// Turns the archived `file` blob stored in each Manifest.db row into a plain
// object graph. For the keychain tool we only need the MBFile record's
// EncryptionKey (bytes) and ProtectionClass (int), but the resolver is general.
(function () {
  'use strict';
  var UID = function () {}; // replaced below with KC.bplist.UID

  function isUID(v) { return v instanceof window.KC.bplist.UID; }

  function unarchive(plistRoot) {
    if (!plistRoot || plistRoot.$archiver !== 'NSKeyedArchiver') {
      throw new Error('Not an NSKeyedArchiver archive');
    }
    var objects = plistRoot.$objects;
    var top = plistRoot.$top;

    function getObject(uid) {
      var v = objects[uid.value];
      if (typeof v === 'string' && v === '$null') return null;
      if (v && typeof v === 'object' && !isUID(v) && !(v instanceof Uint8Array) && !Array.isArray(v) && v.$class) {
        var cls = objects[v.$class.value];
        var className = cls && cls.$classname;
        switch (className) {
          case 'NSMutableDictionary':
          case 'NSDictionary': {
            var keys = v['NS.keys'] || [];
            var vals = v['NS.objects'] || [];
            var m = {};
            for (var i = 0; i < keys.length; i++) {
              m[String(coerce(keys[i]))] = coerce(vals[i]);
            }
            return m;
          }
          case 'NSMutableData':
          case 'NSData':
            return v['NS.data'];
          case 'NSMutableArray':
          case 'NSArray':
          case 'NSSet':
          case 'NSMutableSet': {
            var a = v['NS.objects'] || [];
            return a.map(coerce);
          }
          case 'NSMutableString':
          case 'NSString':
            return v['NS.string'];
          case 'NSDate':
            return Math.floor(v['NS.time']) + 978307200; // -> unix seconds
          default: {
            var out = { _type: className };
            for (var k in v) {
              if (v.hasOwnProperty(k) && k.charAt(0) !== '$') out[k] = coerce(v[k]);
            }
            return out;
          }
        }
      }
      return v;
    }

    function coerce(x) {
      if (isUID(x)) return getObject(x);
      return x;
    }

    var rootUid = top && (top.root || top.$0 || top[Object.keys(top)[0]]);
    return getObject(rootUid);
  }

  window.KC = window.KC || {};
  window.KC.nskeyed = { unarchive: unarchive };
})();
