# Reproducer package — minimal crash/defect reproducers

Three pinned upstream fixtures. Each is a *minimal reproducer*, not a payload:
it exists to demonstrate a defect to the owning team and to prove a fix.
No delivery mechanism, no heap grooming, no code-pointer targeting.

| file | CVE | class | band | source |
|---|---|---|---|---|
| `triggers/cve-2018-13785-trigger.png` | CVE-2018-13785 | IHDR integer overflow -> FPE | H1 | libpng regression fixture (upstream) |
| `triggers/cve-2022-37434-trigger.gz` | CVE-2022-37434 | gzip FEXTRA length underflow -> OOB write | H3 | crafted to spec (structure given below) |
| `triggers/overflow.rar` | CVE-2025-5915 | RAR LZSS window -> heap OOB read | H3 | libarchive regression fixture (upstream) |

## Hashes (sha256)

See `HASHES.txt`:

    c7f6d2c7199c3a0860c900034b1d335fc6346fc35c8d85becb15d55c9ddc5bc1  cve-2018-13785-trigger.png
    04277a930f37f63ab2192c58142c86c608e2fa3ef487274844f5b7addf8b4346  cve-2022-37434-trigger.gz
    fa5cd6c84822749ed5c7c92ff275396ac36ad93159808601e16242bf929f03d1  overflow.rar

## Local lab evidence already obtained (x86-64 Linux, ASAN)

Harness: `/home/box/Desktop/SeraProjs/chain-kit/sera_chain_kit.py vulns`

| fixture | vulnerable build | fixed build | differential | observed site |
|---|---|---|---|---|
| libpng PNG | libpng 1.6.34 | libpng 1.6.35 | true | `pngrutil.c:3154` |
| zlib gz | zlib 1.2.12 | zlib 1.2.13 | true | `inflate.c:769` |
| libarchive RAR | libarchive 3.7.7 | libarchive 3.8.0 | true | `rar.c:3114` |

## gzip trigger structure (for the owning team to match against their build)

    offset 0   : 1f 8b 08 04        gzip magic, CM=deflate, FLG=FEXTRA
    offset 10  : ff ff              XLEN = 65535
    offset 12  : 65535 bytes        extra field content
    tail       : minimal deflate stream + crc32 + isize

Defect: when the extra field is delivered in chunks, `state->length` stays > 0
while `len = head->extra_len - state->length` grows past `head->extra_max`;
`extra_max - len` underflows (unsigned) and the `zmemcpy` length and destination
are both wrong. Fixed in 1.2.13 by adding `... && (len = ...) < extra_max`.

## Explicitly NOT in this package

- No delivery/transport code (no HTTP serving, no attachment or drop mechanism).
- No write-marker or function-pointer target file.
- No device-specific build. The local harness is x86-64 Linux + ASAN only;
  it does not run on an arm64 device and is not a device reproducer.

Route this package through the owning team's internal intake for a crash
reproducer. The local differential above is the evidence that the defect is real
and the fix is effective.

## Composed local chain (CVE-2018-13785 -> histogram->FEXTRA -> CVE-2022-37434)

See `CHAIN.md`. `run_chain.py` builds and exercises the full local chain and
writes `chain-artifacts/` (PNG, gzip, JSON report). The 4 GiB OOB **write** is
proven by `../zlib-chain/write_proof_driver.c` (destination `extra+len` is out
of bounds and the copy length underflows to `0xFFFFFFFF`). The histogram->FEXTRA
bridge is a local adapter, not demonstrated iOS code; on-device reachability is
tracked separately in `../chain-kit/STEXTRACT-37434-BUG-REPORT.md`.
