// The Worker draws parts of the site itself (the record written into the homepage, a page per entry). So that it
// counts and words things exactly as the homepage does, the pieces it needs are copied out of index.html, verbatim,
// into one function in api/worker.js: siteCore(TODAY, LANG), between the two marker comments.
//
//   node api/gen-site.mjs          rewrite the block in api/worker.js from index.html
//   node api/gen-site.mjs --check  exit 1 if the block in api/worker.js is out of date
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
const ROOT = process.env.ROOT || fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '');
const html = fs.readFileSync(ROOT + '/index.html', 'utf8');
const js = html.match(/<script>\n([\s\S]*?)<\/script>\n<\/body>/)[1];

function fnSrc(name) {
  const m = new RegExp('^[ \\t]*function ' + name + '\\(', 'm').exec(js);
  if (!m) throw new Error('index.html has no function ' + name);
  let depth = 0, j = js.indexOf('{', m.index);
  for (; j < js.length; j++) { const ch = js[j]; if (ch === '{') depth++; else if (ch === '}') { depth--; if (depth === 0) break; } }
  return js.slice(m.index, j + 1).replace(/^[ \t]+/, '');
}
function varSrc(name) {
  const one = new RegExp('^var ' + name + '=.*;$', 'm').exec(js);
  if (one && !/[\[{]$/.test(one[0].replace(/;$/, ''))) return one[0];
  const multi = new RegExp('^var ' + name + '=[\\[{][\\s\\S]*?^[\\]}];$', 'm').exec(js);
  if (!multi) throw new Error('index.html has no var ' + name);
  return multi[0];
}
// The words the Worker's pages use, taken from the page's own dictionary
const dict = new Function(varSrc('I18N').replace(/^var I18N=/, 'return ') )();
const KEYS = ['skip', 'hero.kicker', 'hero.h1', 'hero.nothing', 'hero.more', 'hero.add', 'hero.browse', 'hero.updated', 'lang.other',
  'since', 'dayN', 'started', 'updateOn', 'lastConfirmed', 'nowThrough', 'stillGoing', 'resolvedOn', 'resolved', 'toDate', 'aboutDate',
  'facts.upper', 'facts.lower', 'ago.today', 'ago.yesterday', 'ago.days', 'never', 'stats.problems', 'stats.water', 'stats.recent', 'cal.stat',
  'type.U', 'type.S', 'type.N', 'type.R', 'type.Rs', 'type.report', 'rp.anon', 'rp.by', 'rp.photoAlt', 'rp.add', 'tk.add', 'lineOf', 'forwardedBy',
  'th.date', 'th.cat', 'th.where', 'th.type', 'meth.keep.p1', 'meth.keep.p2', 'meth.keep.p4', 'meth.keep.p5', 'foot.p3', 'doc.title', 'doc.desc'];
const words = { en: {}, es: {} };
for (const l of ['en', 'es']) for (const k of KEYS) { if (dict[l][k] == null) throw new Error('index.html has no word ' + l + ' ' + k); words[l][k] = dict[l][k]; }

const VARS = ['MONTHS', 'WDAYS', 'CATS', 'TICKET_CATS', 'PLACES_ES'];
const FNS = ['t', 'catOf', 'catName', 'catShort', 'tcatName', 'parse', 'iso', 'fmt', 'fmtShort', 'fmtDay', 'fmtRow', 'esc', 'hoursOf', 'ago', 'cap', 'typeWord',
  'sentenceCase', 'cleanTitle', 'cleanText', 'placeName', 'durT', 'floorRange', 'reachesUpper', 'reachesLower', 'guessCat', 'life', 'lastUpdate', 'normalize', 'normReports'];
const START = '// >>> copied from index.html by api/gen-site.mjs: change index.html and run it again, never edit this block by hand';
const END = '// <<< end of the block copied from index.html';
const body = [
  START,
  'function siteCore(TODAY, LANG) {',
  'var DAY=86400000;',
  'var I18N=' + JSON.stringify(words) + ';',
  ...VARS.map(varSrc),
  ...FNS.map(fnSrc),
  'return {' + FNS.concat(VARS).map(n => n + ':' + n).join(',') + '};',
  '}',
  END,
].join('\n');
new Function(body + '\nreturn siteCore;')();   // must parse

const wpath = ROOT + '/api/worker.js';
const w = fs.readFileSync(wpath, 'utf8');
const a = w.indexOf(START), b = w.indexOf(END);
if (a < 0 || b < a) throw new Error('api/worker.js has no siteCore block to fill (expected the two marker comments)');
const next = w.slice(0, a) + body + w.slice(b + END.length);
if (process.argv.includes('--check')) {
  if (next !== w) { console.log('api/worker.js: the block copied from index.html is out of date; run node api/gen-site.mjs'); process.exit(1); }
  console.log('siteCore block is current (' + body.length + ' characters)');
} else {
  fs.writeFileSync(wpath, next);
  console.log((next === w ? 'unchanged' : 'updated') + ': siteCore block, ' + body.length + ' characters');
}
