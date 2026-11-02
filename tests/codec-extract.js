/**
 * Stegoframe codec extractor (tests/codec-extract.js)
 *
 * Kills the test copy-drift class for good: instead of mirroring the codec
 * functions inside the test file, the tests evaluate the SAME code the
 * browser runs. `index.html` marks the block the tests own with
 * `<<<STEGOFRAME_CODEC_START>>>` / `<<<STEGOFRAME_CODEC_END>>>`; this module
 * slices that block out, wraps it in a Function with the browser globals the
 * block uses (crypto), and hands back the real definitions.
 *
 * Why this exists: the previous test file carried a hand-copied `_lsbExtract`
 * that had an SGF branch the app did not - a stale copy that graded green
 * while the shipped reader disagreed with the writer. A copy of code is a
 * claim about code; this makes the claim checkable by construction.
 *
 * The block is plain ES (no imports, no React) by design: it only touches
 * `crypto` and the two DOM carriers (`document`/`Image`, which only
 * `lsbWrite`/`lsbRead` need and the Node tests never call). Node >=18 exposes
 * `webcrypto`; the bare `crypto` global only lands in Node 19, so it is
 * injected here rather than relied on.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { webcrypto } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = join(HERE, '..', 'index.html');

const START = '<<<STEGOFRAME_CODEC_START>>>';
const END = '<<<STEGOFRAME_CODEC_END>>>';

/** Extract the raw codec block text from index.html. Throws if the markers move. */
export function extractCodecSource() {
  const html = readFileSync(INDEX, 'utf8');
  const a = html.indexOf(START);
  const b = html.indexOf(END);
  if (a === -1 || b === -1 || b <= a) {
    throw new Error(
      `codec markers missing or misordered in index.html (${START} / ${END}); ` +
      'the extractor cannot see the real codec block'
    );
  }
  // Skip the rest of the START marker's own comment line; the END marker sits
  // on its own line so its line start is the natural cut.
  const from = html.indexOf('\n', a) + 1;
  const to = html.lastIndexOf('\n', b) + 1;
  return html.slice(from, to);
}

/**
 * Evaluate the extracted block and return its real definitions.
 * The block's only non-standard global is `crypto`; it is injected.
 */
export function loadCodec() {
  const src = extractCodecSource();
  const NAMES = [
    '_PI', '_SB', '_IB', '_BRN', '_VR', 'Enc', '_ROOM_SALT',
    'deriveRoomId', '_toHex', '_fromHex', '_dk', '_ae', '_ad', '_pk', '_up',
    '_barr2b', '_lsbPayload', '_lsbExtract', 'lsbWrite', 'lsbRead',
  ];
  const factory = new Function(
    'crypto',
    `"use strict";\n${src}\nreturn { ${NAMES.join(', ')} };`
  );
  const codec = factory(webcrypto);
  for (const n of NAMES) {
    if (!(n in codec)) throw new Error(`codec block did not define ${n}`);
  }
  return codec;
}
