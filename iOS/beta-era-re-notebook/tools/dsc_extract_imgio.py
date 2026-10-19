#!/usr/bin/env python3
# dsc_extract_imgio.py -- extract ImageIO __TEXT from the split dyld_shared_cache
# (no external tool). Maps vaddr -> logical file offset via the cache header
# mappings, then logical offset -> (subcache file, offset) via cumulative sizes.
import struct, os, glob, sys

DSC = "/home/box/.hermes/profiles/seraphine/cache/scratch/dsc/22H352__iPhone11,8"
OUT = "/home/box/.hermes/profiles/seraphine/cache/scratch/imgio"
os.makedirs(OUT, exist_ok=True)

main = os.path.join(DSC, "dyld_shared_cache_arm64e")
subs = sorted([f for f in glob.glob(os.path.join(DSC, "dyld_shared_cache_arm64e.*"))
               if f.rsplit(".", 1)[-1].isdigit()],
              key=lambda f: int(f.rsplit(".", 1)[-1]))
files = [main] + subs
sizes = [os.path.getsize(f) for f in files]
cum = [0]
for s in sizes: cum.append(cum[-1] + s)
print(f"logical cache: {cum[-1]/1e9:.2f} GB across {len(files)} files")

hd = open(main, 'rb').read(0x4000)
print("magic:", hd[:16])
mappingOffset, mappingCount = struct.unpack_from("<II", hd, 16)
f = open(main, 'rb'); f.seek(mappingOffset)
maps = []
for _ in range(mappingCount):
    addr, size, foff, maxp, initp = struct.unpack("<QQQII", f.read(32))
    maps.append((addr, size, foff))
f.close()
for (a, s, fo) in maps: print(f"  map vaddr={hex(a)} size={hex(s)} fileOff={hex(fo)}")

def read_logical(off, n):
    for i in range(len(files)):
        if cum[i] <= off < cum[i+1]:
            fh = open(files[i], 'rb'); fh.seek(off - cum[i])
            d = fh.read(n); fh.close(); return d
    raise IOError(f"offset {hex(off)} out of range")

def vaddr_to_foff(v):
    for (addr, size, foff) in maps:
        if addr <= v < addr + size:
            return foff + (v - addr)
    return None

# ImageIO __TEXT.__text: vaddr 0x18864c638, size 0x469050 (from prior Mach-O iS)
TGT, SIZE = 0x18864c638, 0x469050
foff = vaddr_to_foff(TGT)
print(f"\nImageIO __text vaddr={hex(TGT)} -> logical fileOff={hex(foff)}")
data = read_logical(foff, SIZE)
out = os.path.join(OUT, "ImageIO_text.bin")
open(out, "wb").write(data)
# sanity: first bytes should be valid arm64 (function prologue)
print(f"extracted {len(data)} bytes -> {out}")
print("first 16 bytes:", data[:16].hex())
print("VBASE (vaddr of offset 0):", hex(TGT))
