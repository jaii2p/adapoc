# TDLib parse_html guided fuzz — clean negative (architecture-consistent)

Status: no crash found over 9.45M coverage-guided runs; the result is an
honest negative explained by parser architecture, not a failed hunt.

## Campaign
- Target: REAL ASAN TDLib parse_html() (coverage-instrumented MessageEntity_cov.o
  + utf8_cov.o linked ahead of clean libs; 68351 counters).
- Dict: html tags/entities/UTF-8 forms. Corpus: 3319 seeds (nested/multibyte).
- Result: cov 1380 / ft 8652, 2217 corpus units, 9,456,394 runs in 601s, EXIT 0.
- No abort, no AddressSanitizer report, no CHECK failure.

## Why this is an honest negative
parse_html (MessageEntity.cpp:3363) is a *producing* parser: it walks the HTML
text and GENERATES entity offsets via its own byte/UTF-16 accounting
(nested_entities.emplace_back(..., utf16_offset, ...)), so the offsets it emits
always agree with the walk it performed. The aborting CHECKs the lens targets
live in the *consuming* normalization path clean_input_string_with_entities
(4241: utf16_offset == entity_end + 1; 4253: utf16_offset == entities[..].offset
+ 1) and only fire when EXTERNALLY supplied entity offsets disagree with the
byte stream.

parse_html cannot feed itself inconsistent offsets, so fuzzing its TEXT input
cannot reach those CHECKs. The mismatch requires an external entity-array
consumer — which is exactly the markdown path (parse_markdown_v3) already
proven in option 1 (SIGABRT at MessageEntity.cpp:2835 on attacker entities).

## Conclusion
- The vulnerability class (external entity offset vs UTF-16 desync -> CHECK
  abort) is REAL and confirmed at the markdown entry.
- The HTML text parser is defensively self-consistent: no bug found despite deep
  guided coverage. To chase the html consumer specifically, the fuzz input
  would need to drive the html->entity normalization feed with attacker entity
  arrays (fix_formatted_text/clean path), not the raw text parser.
- Honest label for this arm: architecture-gated negative, not a finding.