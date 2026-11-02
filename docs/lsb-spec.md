# LSB carrier wire spec (v1.1)

The LSB (PNG) carrier ships BOTH a fix for a reader/writer that never
agreed, and a framing standard shared with Vant's `lib/stego.js` PNG
pipeline (pass 178). This doc pins the wire so future changes keep both
systems reading each other.

## The bug this PR fixes

`lsbRead` referenced a helper (`_b2B`, bits→bytes) that was never defined
in `index.html` — every `onload` threw a `ReferenceError` inside the
promise and the read NEVER resolved: LSB decode silently hung forever.
Even with that fixed, the reader expected an 8-byte SGF binary header
(`0x534746` magic + version + u32 length) that `lsbWrite` (and the SVG
path) never emitted — the writer produced a bare packet with no framing.
Writer and reader could never talk to each other. The README/AGENTS docs
also documented this SGF header (and an SVG `data-p=` extraction snippet
that doesn't match the SVG code either) — updated in this PR.

## Canonical LSB wire (shared with Vant lib/stego.js)

```
bit stream:  MSB-first over UTF-8 bytes, ONE bit per pixel, taking the
             LSB of the RED channel byte of each pixel (ImageData order
             R,G,B,A → only index i*4 carries a bit), traversed
             x-major (left-to-right, top-to-bottom).

byte stream: [4-byte big-endian payload length N][N payload bytes]

payload:     the packet string, i.e. "BRN:ENC:<hex>" where
             <hex> = hex(salt):hex(iv):hex(authTag):hex(ciphertext)
             (AES-256-GCM, PBKDF2-SHA256 100k, salt 16B, IV 16B —
             unchanged from v1.0 and Vant-compatible).
```

Notes:

- The length header covers ONLY the packet (not itself). Read side:
  `N = readUInt32BE(0)`, packet = bytes[4, 4+N).
- Reader semantics: a length that is absurd (0, negative-as-unsigned beyond
  capacity) ⇒ no payload. A length that parses but whose payload does not
  start with the `BRN:` magic (colon INCLUDED) ⇒ empty, not a payload —
  this is how a random noise image ("looks like static") is told apart
  from a stone that isn't in our dialect.
- Carrier carrying capacity is NOT part of the wire: any producer may pick
  square dimensions ≥ ceil(sqrt((N+4)*8)), min 32×32 (we keep the writer's
  noise background + alpha=255 so the image still looks like static and
  never transparent). A reader must not assume the payload fills the image.

## Cross-system compatibility

Because Vant's PNG pipeline (lib/stego.js `_lsbRoundTrip`, pass 178)
now emits the identical wire, a stone written by one decodes in the
other with zero conversion:

| Producer | Consumer | Works |
|---|---|---|
| Stegoframe LSB (this spec) | Vant `stego.decode` | yes |
| Vant `stego.encode` (PNG) | Stegoframe `lsbRead` | yes (canvas-rasterized stone) |
| Stegoframe SVG | Vant `decodeSvg` | yes (previous interop pass) |
| Vant encodeSvg | Stegoframe `svgRead` | yes (previous interop pass) |

Desktop/test interop note: `stego.decode` operates on the DECODED
pixel stream of a real PNG (zlib-inflated, unfiltered), while
Stegoframe operates in the browser on a already-rasterized canvas. Both
is the same wire — the bit layout is identical once the image is
treated as a flat pixel stream. Vant re-filters to filter-type None on
re-emit (spec-legal). Browser rasterization of a Vant-written PNG gives
the same R-channel sequence (carriers written by Vant use a noise
background; carriers written by Stegoframe use noise too — random data
on encode means the LSB plane of an untouched pixel is unpredictable,
which strengthens steganographic cover, and the length header still
reparses).

## The v1.0 compatibility story

- SVG path: unchanged from v1.0 (and from the Vant interop pass) —
  still `BRN:ENC:<hex>` base64 in `<brn:secret>`. Nothing moves.
- LSB path: the wire CHANGED vs. v1.0, but the v1.0 LSB path was already
  unshippable (see bug section): no stone written by v1.0 could ever have
  been read back by v1.0. There is no compatibility debt to carry:
  LSB stones can simply be re-encoded. The SGF binary magic is dropped
  from the read path too (it never existed on any write path).

## Reader pseudocode (drop-in for any platform)

```js
// d = flat RGBA pixel bytes (alpha channel present, length%4==0)
function readLsb(d) {
  const capacity = Math.floor(d.length / 4);      // one bit per pixel
  if (capacity < 4) return null;
  const bits = new Array(Math.min(capacity * 8, 65536 * 8));
  for (let i = 0; i < bits.length; i++) bits[i] = d[i * 4] & 1;
  const bytes = bitsToBytesMsbFirst(bits);
  const len = (bytes[0]<<24) | (bytes[1]<<16) | (bytes[2]<<8) | bytes[3];
  if (!Number.isSafeInteger(len) || len <= 0 || 4 + len > bytes.length) return null;
  const packet = utf8Decode(bytes.slice(4, 4 + len));
  return packet.startsWith("BRN:") ? packet : "";
}
```

Implementations:

- Stegoframe (browser): `_lsbExtract` in `index.html` + `lsbRead`.
- Vant (Node): `extractData`/`_lsbRoundTrip(writeMode=false)` in
  `lib/stego.js` on dhaupin/vant branch `axolotl` (pass 178).
