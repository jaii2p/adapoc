# TDLib markdown-v3 metric-mismatch — UTF-16/byte desync process abort (SIGABRT)

CWE-617 (reachable assertion) — Telegram TDLib, `td/telegram/MessageEntity.cpp`.
Status: **CONFIRMED end-to-end** — at the real ASAN TDLib build
(`parse_markdown_v3`) aborts at `MessageEntity.cpp:2835`.

## Trigger
```
text     = "é**x**"                 (é = 2-byte UTF-8)
entities = { Bold, offset=5, length=2 }
parse_markdown_v3(FormattedText{text, entities})
```
Real ASAN build output:
```
[MessageEntity.cpp:2835] Check `entity.offset + entity.length <= utf16_offset` failed
Aborted (core dumped)   -> exit 134 (SIGABRT)
```

## Mechanism (source-verified)
`parse_markdown_v3_without_pre` walks text **by bytes** (`for i<text.size()`) while
tracking a UTF-16 code-unit counter (`utf16_offset += 1 + (c>=0xf0)`); at a
markup boundary it does `i++` (skip **one byte**) beside `utf16_offset++`. A
multibyte char at/near the entity boundary desyncs byte-stream and UTF-16-stream;
the trailing invariant
```
CHECK(entity.offset + entity.length <= utf16_offset)
```
fires → `abort()`. Any attacker-supplied entity whose offset/length misaligns
with the byte-walked `utf16_offset` triggers it.

## PoCs
- `poc/poc_markdown_v3_metric_mismatch.cpp` — **build-independent** reproduction.
  It includes the *verbatim* extracted parser (`fuzz_utf16_harness.cpp`) with
  `CHECK -> __builtin_trap()` and drives the two confirmed cases + a control:
  | run | result |
  |---|---|
  | TRIGGER 1 `é**x**` off=5 len=2 | **SIGILL** (exit 132) |
  | TRIGGER 2 `**` off=8 len=0x7878 | CHECK fires |
  | CONTROL `**bold**` off=0 len=4 | clean |
  ```
  g++ -O1 -g -o poc_markdown_v3_metric_mismatch poc_markdown_v3_metric_mismatch.cpp
  ./poc_markdown_v3_metric_mismatch
  ```
- `poc/proof_min_realbuild.c` — the minimal reproducer against the **real** ASAN
  TDLib build (17-line C++; needs the full build).
- `poc/fuzz_utf16_harness.cpp` — the standalone extraction (verbatim parser +
  documented substitutions), libFuzzer entry included.

## Reachability (confirmed path)
End-to-end confirmed: `parse_markdown_v3` is actually called on the constructed
attacker-entity input and aborts. Reachable when the client has
`always_parse_markdown` enabled (OptionManager.cpp:909) or via the
`get_markdown_v3` round-trip — both feed caller/user entities into this parser.
`REACHABILITY-MAP.md` details gates (`fix_formatted_text`/`skip_trim`,
`remove_invalid_entities`) and `CAMPAIGN.md` the fuzz campaign.

## Impact
Remote process crash / DoS of the TDLib client on a crafted message's entity
offsets. Not (yet) shown to be memory corruption/RCE — the fault is a defensive
bounds-invariant CHECK abort, not a wild write. (SIGABRT, exit 134.)

## Honest scope
- `HONEST-NEGATIVE-html-parser.md` records that `parse_html` (the *producing*
  parser) is self-consistent and found no bug over 9.45M coverage-guided runs —
  the confirmed entry is the *consuming* markdown path, not html.
- The full-build reproduction removes the earlier `fix_formatted_text`/skip_trim
  reachability doubt raised in the pre-full-build campaign docs.

## Files
- `REPORT.md` — full confirmed DoS report
- `REACHABILITY-MAP.md` — reachability map (loading gates)
- `CAMPAIGN.md` — fuzz campaign results
- `HONEST-NEGATIVE-html-parser.md` — 9.45M-run clean negative
- `poc/*` — build-independent PoC + real-build reproducer + harness