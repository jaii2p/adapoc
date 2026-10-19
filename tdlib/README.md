# tdlib — confirmed findings

Vulnerability research against Telegram **TDLib** (`td/telegram/MessageEntity.cpp`),
static-first then a dict-assisted chained-mutation fuzz campaign, with the
landing confirmed end-to-end on the **full ASAN build** of the library (codegen
+ actor + real libs), not just a macro extraction.

| finding | type | trigger | confirmed |
|---|---|---|---|
| [`markdown-v3-metric-mismatch/`](markdown-v3-metric-mismatch/) | CWE-617 reachable-assert — UTF-16/byte desync in `parse_markdown_v3` | `"é**x**"` + `{Bold,5,2}` | YES — SIGABRT at MessageEntity.cpp:2835 (real ASAN build) |

Also shipped in that folder for completeness and honesty: the **reachability map**
and **fuzz campaign** docs that led to the confirmation, and the **clean negative**
for the html-parser arm (9.45M coverage-guided runs, no crash — architecture-gated
negative, explicitly labeled as not a finding).

The PoC folder carries both a **build-independent** reproduction (verbatim parser
extraction, `CHECK -> trap`, works with just g++) and the minimal reproducer
against the **real** ASAN TDLib build.