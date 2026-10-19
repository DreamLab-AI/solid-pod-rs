// Regenerates expected.json from corpus.json using the JSS parser path.
//
// Oracle: JSS 0.0.221 src/rdf/turtle.js turtleToJsonLd(), which calls
// `new Parser({ baseIRI })` from n3.js (^1.26.0) with no format option.
//
// Usage: node gen.mjs <path-to-n3-module-dir> > expected.json
//   e.g. node gen.mjs /home/devuser/workspace/.tmp/jss221/plugins/node_modules/n3
//
// Each entry is either { error } (JSS threw) or { triples, restricted };
// `restricted` is true when the document used quoted graphs or variables,
// which the Rust side deliberately refuses (415).
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const n3dir = path.resolve(process.argv[2]);
const { Parser } = createRequire(import.meta.url)(n3dir);
const corpus = JSON.parse(readFileSync(new URL('./corpus.json', import.meta.url), 'utf8'));
const XSD_STRING = 'http://www.w3.org/2001/XMLSchema#string';
const LANG_STRING = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#langString';

function term(t) {
  switch (t.termType) {
    case 'NamedNode': return { t: 'iri', v: t.value };
    case 'BlankNode': return { t: 'bnode', v: t.value };
    case 'Literal': {
      const o = { t: 'lit', v: t.value };
      if (t.language) o.lang = t.language;
      else if (t.datatype && t.datatype.value !== XSD_STRING && t.datatype.value !== LANG_STRING) o.dt = t.datatype.value;
      return o;
    }
    default: return { t: t.termType.toLowerCase(), v: t.value };
  }
}

const out = {};
for (const doc of corpus) {
  const parser = new Parser({ baseIRI: doc.base });
  let quads;
  try {
    quads = parser.parse(doc.text);
  } catch (e) {
    out[doc.name] = { error: String(e.message).split('\n')[0] };
    continue;
  }
  const triples = [];
  let restricted = false;
  for (const q of quads) {
    if (q.graph.termType !== 'DefaultGraph') restricted = true;
    for (const x of [q.subject, q.predicate, q.object]) {
      if (x.termType === 'Variable') restricted = true;
    }
    triples.push([term(q.subject), term(q.predicate), term(q.object)]);
  }
  out[doc.name] = { triples, restricted };
}
console.log(JSON.stringify(out, null, 1));
