# TDLib markdown-v3 UTF-16/byte metric-mismatch — campaign results

Status: ALGORITHM-LEVEL CONFIRMED (verbatim shipped code, in-silico).
Crash class: ONE root cause, multiple triggers (all fold into a single
invariant).  Reachability to a CVE-level public claim: PARTIAL (see below).

## The confirmed invariant failure
parse_markdown_v3_without_pre (td/telegram/MessageEntity.cpp 2773-2842):
splittable-entity removal loop walks text BYTES while tracking a UTF-16
code-unit counter; on a markup boundary it does `i++` (skip one byte) beside
`utf16_offset++`.  A multibyte character (or an entity that survives past the
text's utf16 length) desyncs the two, and:

    CHECK(entity.offset + entity.length <= utf16_offset)   // fails -> abort

In the standalone faithful harness the CHECK is __builtin_trap(), which
libFuzzer surfaced as crashes.

## Fuzz campaign (dict-assisted chained text x entity mutations, 8 min x2)
- cov 186 / ft 245 / corp 13 units: the harness built entity-covered and
  markup structures; mutations pushed entity offsets/lengths into the seam.
- Two crash artifacts, BOTH resolve to the same line 255 invariant:
    * fuzz_runs/crash-...790ed3a (16B): `**` text + entity off=8 len=0x7878
      (out-of-range length much larger than the 5-byte text).
    * fuzz_runs/crash-...e52ed1c (15B): `é**x**` + entity off=5 len=2
      (markup-boundary tail on multibyte text).
- gdb on both: parse_markdown_v3_without_pre @ harness.cpp:255 (the
  offset+length<=utf16_offset CHECK).  Same class, not new seams.

## Reachability (the honest gated claim)
The seam is reachable in production IF:
1. An attacker-supplied entity whose offset+length exceeds the text's utf16
   length SURVIVES fix_formatted_text.  That clamp (l.4625) is gated on
   skip_trim==false; many inbound/text paths pass skip_trim=true, so the clamp
   is bypassed (only the [0,1e6] per-field range is enforced at 4577-82, and
   remove_invalid_entities at 4354 does NOT drop out-of-range entities).
2. The markdown entry is reached: either the opt-in option
   "always_parse_markdown" is enabled on the client (OptionManager.cpp:909),
   or the get_markdown_v3 round-trip (l.3308) with all-user entities.
This makes it a STRONG remote-DoS candidate, but full-build end-to-end
confirmation (the fix_formatted_text/search-and-replace path dragging
UserManager/td classes we stubbed) is required before a public CVE-level
claim.  Honest label: pending full-build proof of the skip_trim=true inbound
path reaching parse_markdown_v3.

## Files (TDLib hunt)
- /home/box/tdlib-hunt/fuzz_utf16_harness.cpp      standalone faithful extraction
- /home/box/tdlib-hunt/fuzz_utf16.dict             markup/utf8 byte dictionary
- /home/box/tdlib-hunt/fuzz_runs/crash-*           the two collated crash artifacts
- /home/box/tdlib-hunt/REPORT... (see map report)
- /home/box/Desktop/aiexclfindings/REPORT-TDLIB-utf16map.md  earlier reachability map

## Method notes
- Macro-extraction of the parser family beat a full TDLib build here: the
  target function was self-contained on Slice+vector<MessageEntity>; only
  find_entities/LinkManager needed honest stubs. Same as the wordexp move.
- Dict pitfall cost two campaign starts (inline #comment after a token aborts
  ParseDictionaryFile; a known trap in the corpus aborts replay unless
  -ignore_crashes=1). Both recorded in the vulnerability-research skill.