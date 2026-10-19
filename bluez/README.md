# BlueZ — confirmed findings (beta era)

Findings from the pre-continuity beta window (seraphine agent, `zdhunt` fuzzer +
BTHunt deep-sink harnesses), confirmed against **BlueZ 5.85/5.87 (installed or
fixture)**. Upstream master was byte-identical at audit time (2026-10-09) for
every report; none is yet vendor-fixed.

## Index

| folder | finding | class | confirmed |
|---|---|---|---|
| [`btmon-sdp-monitor-overflow/`](btmon-sdp-monitor-overflow/) | uint32 overflow → `alloca`/`strncpy` OOB write+read in `monitor/sdp.c` (file + LIVE socket crash on stock `btmon`) | CWE-190 → CWE-787/125 | YES — SIGSEGV stock binary, file 6/6 & socket 3/3 |
| [`btmon-sdp-decoder-oob/`](btmon-sdp-decoder-oob/) | hcidump `tools/parser/sdp.c` three OOB reads/emits (string walk, AttributeByteCount offset, cont-state loop) | CWE-125 → CWE-200 | YES — ASAN READs + **stock emission** (silent heap leak) |
| [`btmon-bnep-hexdump-leak/`](btmon-bnep-hexdump-leak/) | `hdr_len=-1` → `packet_hexdump(uint16 wrap)` → 69 KB process leak (env, pointers) + SIGSEGV | CWE-125/191 → CWE-200 | YES — stock `btmon`, 69,675 B leaked |
| [`mesh-pb-adv-oob-write/`](mesh-pb-adv-oob-write/) | Mesh PB-ADV SAR START unchecked `memcpy(len-3)` → **heap OOB WRITE** (`mesh/pb-adv.c:430`); silent in-chunk corruption injects `user_data` | CWE-787 | YES — ASAN WRITE; callback-deref escalation (H7) **removed**, write is the terminal verified rung |
| [`gobex-misaligned-load/`](gobex-misaligned-load/) | `gobex-header.c` UNICODE decode casts odd-addr payload to `gunichar2` → **misaligned load (C UB)**, wire-reachable; negative control proves no OOB behind it | C UB (not memory corrupt) | YES — UBSan; `-fno-sanitize=alignment` + 120k execs = 0 further faults |
| [`obexd-path-confusion/`](obexd-path-confusion/) | `verify_path` prefix-confusion (out-of-root dir listing) + `open(O_TRUNC)` before verify (destructive side effect before rejection) | CWE-22 / CWE-59 | gate-level YES (harness, real `filesystem.o`); full daemon flow labelled candidate |

## Honest notes

- **BlueZ per-finding statuses differ in reachability class**: the SDP
  monitor/decoder/BNEP items are crash+disclosure proven end-to-end on the stock
  distro binary; the MESH PB-ADV write is proven at the decoder rung (extended
  advertising / long-AD precondition affects reachability to a live peer); the
  obexd items are gate-level proven on the real plugin with the symlink
  precondition called out honestly. Every report carries its own
  verified-vs-candidate boundary.
- **gobex misaligned-load** (added from the BTHunt ledger) is the one GoBEEx
  finding: a confirmed C-UB misaligned load (wire-reachable), with a negative
  control proving no OOB hides behind it — LOW severity, not memory corruption.
- The bundled `re-log.md` (moved to `beta-era-btmon-mesh-gate-hunt-log.md` space
  via the iOS RE notebook) is the live beta hunt log, not a finding.
- No CVE assigned to any of these as of audit date; all upstream-unpatched.

## Per-folder contents

- `poc/` — the actual saved trigger binaries (`.bin`), the live-socket probe,
  and the seed/generator scripts used to reproduce. `btmon -r <trigger>` or the
  documented harness repro each.