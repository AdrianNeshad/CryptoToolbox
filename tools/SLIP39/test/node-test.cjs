#!/usr/bin/env node
/*
 * Known-answer and property tests for the SLIP-39 tool.
 * Runs fully offline against the tool's own lib/ code.
 *
 *   node tools/SLIP39/test/node-test.cjs
 *
 * vectors.json is the official SLIP-0039 test-vector file, taken verbatim from
 * trezor/python-shamir-mnemonic (45 cases: valid and invalid share sets, 128/256
 * bit, extendable and non-extendable). Each valid set must combine to the given
 * master secret with passphrase "TREZOR", and the BIP-32 master xprv derived
 * from it (with the vendored bitcoinjs the UI uses) must match; every invalid
 * set must be rejected.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const TOOL = path.resolve(__dirname, '..');
global.window = global;
require(path.join(TOOL, '../BIP39-checksum/bip39_english.js'));
require(path.join(TOOL, 'lib/wordlist.js'));
const S = require(path.join(TOOL, 'lib/slip39.js'));
const B39 = require(path.join(TOOL, 'lib/bip39.js'));
const bitcoinjs = require(path.join(TOOL, '../BIP38-keycompression/bitcoinjs-3.3.0.js'));
const bitcoin = bitcoinjs.bitcoin;
const NodeBuffer = bitcoinjs.Buffer.Buffer;

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (extra ? '  — ' + extra : '')); }
}
const hex = S.bytesToHex;
function xprvOf(ms) { return bitcoin.HDNode.fromSeedBuffer(NodeBuffer.from(ms), bitcoin.networks.bitcoin).toBase58(); }
function randInt(lo, hi) { return lo + nodeCrypto.randomInt(hi - lo + 1); }
function shuffle(a) { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = nodeCrypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }

async function vectorTests() {
  console.log('\nOfficial SLIP-0039 vectors (strict combine, passphrase "TREZOR")');
  const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors.json'), 'utf8'));
  for (const [desc, mnemonics, secretHex, xprv] of vectors) {
    if (secretHex) {
      try {
        const ms = await S.combineMnemonics(mnemonics, 'TREZOR');
        check(desc, hex(ms) === secretHex && xprvOf(ms) === xprv, hex(ms));
      } catch (e) { check(desc, false, e.message); }
    } else {
      try {
        const ms = await S.combineMnemonics(mnemonics, 'TREZOR');
        check(desc + ' (must fail)', false, 'combined to ' + hex(ms));
      } catch (e) { check(desc + ' (rejected: ' + e.message.slice(0, 60) + ')', true); }
    }
  }

  console.log('\nFlexible recovery (UI path) agrees on every valid vector');
  for (const [desc, mnemonics, secretHex] of vectors) {
    if (!secretHex) continue;
    const shares = mnemonics.map(S.decodeShare);
    const ems = await S.recoverEmsFlexible(S.analyzeShares(shares));
    const ms = await S.decrypt(ems.ciphertext, 'TREZOR', ems.iterationExponent, ems.identifier, ems.extendable);
    check(desc.replace(/^(\d+)\..*/, 'vector $1'), hex(ms) === secretHex);
  }

  console.log('\nFlexible recovery tolerates surplus shares (vector 17 set + vector 18 extra share)');
  {
    const all = vectors[16][1].concat(vectors[17][1]);
    const ems = await S.recoverEmsFlexible(S.analyzeShares(all.map(S.decodeShare)));
    const ms = await S.decrypt(ems.ciphertext, 'TREZOR', ems.iterationExponent, ems.identifier, ems.extendable);
    check('surplus shares still recover ' + vectors[16][2].slice(0, 8) + '…', hex(ms) === vectors[16][2]);
  }
  return vectors;
}

async function roundTripTests() {
  console.log('\nRandom round trips (generate → random minimal subset → combine)');
  const schemes = [
    [1, [[1, 1]]], [1, [[2, 3]]], [1, [[3, 5]]], [1, [[1, 1], [3, 5]]],
    [2, [[1, 1], [2, 3], [3, 5]]], [3, [[2, 2], [1, 1], [4, 6], [2, 3]]], [1, [[16, 16]]], [16, Array(16).fill([1, 1])]
  ];
  let i = 0;
  for (const [gt, groups] of schemes) {
    for (const bytes of [16, 32, 64]) {
      const ms = nodeCrypto.randomBytes(bytes);
      const ext = i % 2 === 0;
      const e = i % 3;
      const pass = i % 2 ? 'pass phrase ' + i : '';
      const res = await S.generateShares({ groupThreshold: gt, groups, masterSecret: new Uint8Array(ms), passphrase: pass, extendable: ext, iterationExponent: e });
      const pick = shuffle(res.groups.map((g, gi) => gi)).slice(0, gt)
        .flatMap(gi => shuffle(res.groups[gi]).slice(0, groups[gi][0]).map(s => s.mnemonic));
      const back = await S.combineMnemonics(shuffle(pick), pass);
      const words = res.groups[0][0].words.length;
      check(`${gt} of [${groups.map(g => g.join('/')).join(' ')}], ${bytes * 8} bit (${words} words), ext=${ext ? 1 : 0}, e=${e}${pass ? ', passphrase' : ''}`,
        hex(back) === ms.toString('hex'));
      i++;
    }
  }

  console.log('\nScheme validation');
  for (const [gt, groups, why] of [[1, [[1, 2]]], [2, [[2, 3]]], [1, [[4, 3]]], [1, [[2, 17]]], [0, [[1, 1]]]].map(x => x)) {
    try { await S.generateShares({ groupThreshold: gt, groups, masterSecret: new Uint8Array(16) }); check('rejects ' + JSON.stringify([gt, groups]), false); }
    catch (e) { check('rejects ' + JSON.stringify([gt, groups]) + ' (' + e.message.slice(0, 50) + '…)', true); }
  }
  for (const [ms, label] of [[new Uint8Array(15), '15-byte secret'], [new Uint8Array(17), 'odd-length secret']]) {
    try { await S.generateShares({ groupThreshold: 1, groups: [[1, 1]], masterSecret: ms }); check('rejects ' + label, false); }
    catch (e) { check('rejects ' + label, true); }
  }
  try { await S.generateShares({ groupThreshold: 1, groups: [[1, 1]], masterSecret: new Uint8Array(16), passphrase: 'åäö' }); check('rejects non-ASCII passphrase', false); }
  catch (e) { check('rejects non-ASCII passphrase', e.code === 'passphrase'); }
}

async function featureTests(vectors) {
  console.log('\nEncoding is byte-exact: re-encoding decoded vector shares gives the same words');
  let same = 0, total = 0;
  for (const [, mnemonics] of vectors) {
    for (const m of mnemonics) {
      let s; try { s = S.decodeShare(m); } catch (e) { continue; }
      total++; if (S.encodeShare(s).join(' ') === m) same++;
    }
  }
  check(`${same}/${total} decodable vector shares re-encode identically`, same === total && total > 50);

  console.log('\nPrefix entry (first 4 letters, as on Trezor devices)');
  {
    const m = vectors[0][1][0];
    const short = m.split(' ').map(w => w.slice(0, 4)).join(' ');
    check('4-letter abbreviations decode to the same share', S.decodeShare(short).words.join(' ') === m);
  }

  console.log('\nExtendable re-share: new identifier, same EMS, any passphrase');
  {
    const [, mn, secretHex] = vectors[42]; // "43. Extendable basic sharing 2-of-3 (128 bits)"
    const ems = await S.recoverEms(S.decodeMnemonics(mn));
    const newId = (ems.identifier + 1234) % 32768;
    const groups = await S.splitEms(2, [[1, 1], [2, 3], [2, 2]], Object.assign({}, ems, { identifier: newId }));
    const pick = [groups[0][0].mnemonic, groups[2][1].mnemonic, groups[2][0].mnemonic];
    const back = await S.combineMnemonics(pick, 'TREZOR');
    check('re-shared set (new id ' + newId + ') combines to the original secret', hex(back) === secretHex);
    const other1 = await S.combineMnemonics(mn, 'another passphrase');
    const other2 = await S.combineMnemonics(pick, 'another passphrase');
    check('…and to the same wallet for a different passphrase too', hex(other1) === hex(other2));
  }

  console.log('\nRegenerating a lost member share reproduces it exactly');
  {
    const res = await S.generateShares({ groupThreshold: 1, groups: [[3, 5]], masterSecret: new Uint8Array(nodeCrypto.randomBytes(32)) });
    const g = res.groups[0];
    let allOk = true;
    for (let lost = 0; lost < 5; lost++) {
      const have = g.filter(s => s.memberIndex !== lost).slice(0, 3).map(s => S.decodeShare(s.mnemonic));
      const re = await S.regenerateMemberShare(have, lost);
      if (re.mnemonic !== g[lost].mnemonic) allOk = false;
    }
    check('each of 5 shares in a 3-of-5 set rebuilt from 3 others', allOk);
  }

  console.log('\nRegenerating a lost 1-of-1 group reproduces it exactly');
  {
    const res = await S.generateShares({ groupThreshold: 2, groups: [[1, 1], [1, 1], [2, 3]], masterSecret: new Uint8Array(nodeCrypto.randomBytes(16)) });
    const have = [res.groups[0][0], res.groups[2][0], res.groups[2][2]].map(s => S.decodeShare(s.mnemonic));
    const ems = await S.recoverEmsFlexible(S.analyzeShares(have));
    const re = await S.regenerateGroup(ems, 1, 1, 1);
    check('group 2 (1-of-1) rebuilt from groups 1 and 3', re[0].mnemonic === res.groups[1][0].mnemonic);
  }

  console.log('\nInconsistent share detection (a valid-checksum share from another set at the same index)');
  {
    const ms = new Uint8Array(nodeCrypto.randomBytes(16));
    const a = await S.generateShares({ groupThreshold: 1, groups: [[2, 4]], masterSecret: ms, identifier: 777 });
    const b = await S.generateShares({ groupThreshold: 1, groups: [[2, 4]], masterSecret: ms, identifier: 777 });
    // Same id/scheme but a different random polynomial: b's share 2 has a valid checksum yet is foreign.
    const mix = [a.groups[0][0], b.groups[0][2], a.groups[0][1], a.groups[0][3]].map(s => S.decodeShare(s.mnemonic));
    const ems = await S.recoverEmsFlexible(S.analyzeShares(mix));
    const rep = ems.report.groups[0];
    check('digest failure → other subset tried, foreign share #3 reported', bytesHex(ems.ciphertext) === bytesHex(a.ems.ciphertext) && rep.inconsistent.join() === '2', JSON.stringify(rep));
  }
  function bytesHex(b) { return hex(b); }

  console.log('\nWord repair (RS1024 erasure decoding)');
  {
    const m = vectors[19][1][0].split(' '); // 33-word share
    const W = S.WORDLIST;
    const res = (ws, deep) => S.repairCandidates(S.resolveWords(ws.join(' ')), { deep });
    const has = (r, words) => r.candidates.some(c => c.words.join(' ') === words.join(' '));

    // Up to 3 erasures are uniquely solvable for a known customization string.
    // Word 2 carries the extendable flag, so 3 erasures that include word 2
    // leave 31 unknown bits against 30 check bits: then a second candidate
    // (with the other flag) can appear — the original is always among them.
    let ok = true;
    for (let t = 0; t < 60; t++) {
      const k = 1 + (t % 3);
      const pos = shuffle([...m.keys()]).slice(0, k);
      const ws = m.slice(); pos.forEach(p => { ws[p] = '?'; });
      const r = res(ws);
      const maxCands = k === 3 && pos.includes(1) ? 2 : 1;
      if (!(has(r, m) && r.candidates.length <= maxCands)) ok = false;
    }
    check('1-3 unreadable words ("?") recovered (60 random trials)', ok);

    ok = true;
    for (let p = 0; p < m.length; p++) {
      const ws = m.slice(); let w; do { w = W[randInt(0, 1023)]; } while (w === m[p]); ws[p] = w;
      const r = res(ws);
      if (!(r.candidates.length === 1 && has(r, m))) { ok = false; break; }
    }
    check('one wrong word at any of the 33 positions → exactly one candidate, the original', ok);

    ok = true;
    for (let p = 0; p < 10; p++) {
      const ws = m.slice(); ws.splice(randInt(0, m.length - 1), 1);
      if (!has(res(ws), m)) ok = false;
    }
    check('one missing word found', ok);

    { const ws = m.slice(); ws.splice(7, 0, 'zero'); check('one extra word found', has(res(ws), m)); }
    { const ws = m.slice(); [ws[10], ws[11]] = [ws[11], ws[10]]; check('two swapped neighbouring words found', has(res(ws), m)); }
    { const ws = m.slice(); ws[4] = 'acadmic'; ws[9] = '?'; const r = res(ws); check('misspelt word + unreadable word', has(r, m)); }
    { const ws = m.slice(); ws[3] = W[(S.WORD_INDEX[ws[3]] + 5) % 1024]; ws[20] = W[(S.WORD_INDEX[ws[20]] + 9) % 1024];
      check('two wrong words found with the deep search', has(res(ws, true), m)); }
    { const ws = m.slice(); ws[1] = '?'; check('unknown word carrying the extendable flag', has(res(ws), m)); }
  }
}

async function bip39Tests() {
  console.log('\nBIP-39 helpers');
  const abandon = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const v = await B39.validate(abandon);
  check('"abandon … about" passes the BIP-39 checksum', v.ok);
  const v2 = await B39.validate(abandon.replace(/about$/, 'abandon'));
  check('bad checksum detected', !v2.ok);
  const seed = await B39.mnemonicToSeed(abandon, 'TREZOR');
  check('seed matches the BIP-39 reference vector',
    hex(seed) === 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04');
  const nodeSeed = nodeCrypto.pbkdf2Sync(Buffer.from(abandon.normalize('NFKD')), Buffer.from('mnemonicTREZOR'), 2048, 64, 'sha512');
  check('seed matches Node\'s own PBKDF2-SHA512', hex(seed) === nodeSeed.toString('hex'));
  const back = await B39.entropyToMnemonic(new Uint8Array(16));
  check('entropyToMnemonic(0×16) = "abandon … about"', back === abandon);

  console.log('\nBIP-39 wallet → 59-word SLIP-39 shares → same seed');
  const res = await S.generateShares({ groupThreshold: 1, groups: [[2, 3]], masterSecret: seed, iterationExponent: 0 });
  const back2 = await S.combineMnemonics([res.groups[0][2].mnemonic, res.groups[0][0].mnemonic], '');
  check(res.groups[0][0].words.length + '-word shares recombine to the 512-bit BIP-39 seed', hex(back2) === hex(seed) && res.groups[0][0].words.length === 59);
}

(async () => {
  const vectors = await vectorTests();
  await roundTripTests();
  await featureTests(vectors);
  await bip39Tests();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
