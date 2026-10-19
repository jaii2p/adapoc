# httpdirfs — heap-buffer-overflow in collect_gumbo_text (CWE-787)

**Status:** CONFIRMED — deterministic heap OOB **WRITE**, reproduced with ASAN
on current master (`86ab2a3`, 2026-10-06). Remote-reachable, pre-auth.

## Report
[`gumbo-heap-overflow/REPORT.md`](gumbo-heap-overflow/REPORT.md)

**TL;DR:** `src/link_parser.c collect_gumbo_text()` (lines ~193-198) accumulates
anchor text with a hard-coded initial capacity of 256 and a growth formula that
under-allocates. Any directory-listing anchor whose inner text is **≥256 bytes**
triggers a heap overflow:
```
<a href="x">AAAA…256 </a>
=> ASAN: heap-buffer-overflow WRITE of size 1 at link_parser.c:195
   (256-byte text) / size N (>256)
```
Boundary mapped cleanly: 255 bytes clean, 256 overflows (size 1), ≥257 overflows
(size N).

## Impact
Memory-corruption WRITE (not just a read). An attacker runs httpdirfs against
their own server (or MITMs an HTTP dir listing) and serves an anchor with large
text → OOB write of up to `len` attacker bytes into adjacent heap — a
write-what-where-adjacent primitive. At minimum a reliable crash (DoS),
potentially corruption. RCE beyond the OOB-write primitive was NOT constructed.

## Repro
```sh
python3 -c "open('/tmp/z.html','wb').write(b'<a href=\"x\">'+b'A'*256+b'</a>')"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 /tmp/zdhunt_html /tmp/z.html
```
`zdhunt_html` drives the real `LinkTable_parse_html()`. Not yet confirmed fixed
upstream.