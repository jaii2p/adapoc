# can-hub — plaintext-transport authorization bypass (F1)

Target: can-hub-io/can-hub @ e7b3653 (2026-10-19). Confirmed live end-to-end on vcan0.

| file | what it is |
|---|---|
| REPORT-F1-PLAINTEXT-AUTHZ-BYPASS.md | full finding: short-circuit analysis, doc/code mismatch, live evidence, fixes |
| f1-demo.sh | reproduction script (needs vcan0) |
| ISSUE-DRAFT.md | coordinated-disclosure issue text |

One-line: every broker authorization check short-circuits to allow for
fingerprint-less peers; plain-TCP peers never carry a fingerprint; therefore any
plaintext-transport peer can sniff and inject CAN frames, configure interfaces,
and register as any agent — and the doc-promised warning for remote exposure
only fires when `--require-known-peers` is also set (off by default).
