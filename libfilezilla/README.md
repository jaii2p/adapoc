# libfilezilla — datetime::set signed-int64 overflow (UB)

**Status:** CONFIRMED (UBSan, stream-reachable, 26-byte trigger) — logic/DoS
class, **RCE NOT established** (authoritative negative sweep on file).

## Report
[`datetime-overflow/REPORT.md`](datetime-overflow/REPORT.md) — the finding.

**TL;DR:** `fz::datetime::set(tm&,…)` does `t_ = (int64_t)tt * 1000`
(`lib/time.cpp:520`) with no magnitude guard. An attacker-controlled RFC-3339
date with a huge `year` drives `timegm()` to a `time_t` whose `* 1000`
overflows signed 64-bit (CWE-190). 26-byte trigger:
```
2147483647-01-15T10:30:00Z
```
The wrapped `t_` corrupts every downstream consumer (get_time_t/get_tm/format/
get_rfc822/arithmetic) of that datetime object.

## The RCE question — answered, negative
[`datetime-overflow/RCE-SWEEP-NEGATIVE.md`](datetime-overflow/RCE-SWEEP-NEGATIVE.md)
is the authoritative memory-sink sweep commanded before any RCE rig. Result:
**no consumer** in libfilezilla 0.57.0 (nor any FileZilla 3.71.0 reachable path)
strings `t_` or a derived tm field into a size/index/allocation. All format/
get_tm/get_rfc822/utimes consumers are bounded. The defect terminates in
benign-wrapped-ms signed arithmetic: CWE-190 logic corruption. **Do not
inflate to Medium/High on the UB alone** — that's the honest severity bar.

## PoC
`poc/`
- `trigger-lfz-datetime-minimal.bin` — 26-byte minimal
- `trigger-lfz-datetime-fuzz.bin` — 68-byte fuzzer-saved

Repro: pipe the trigger into the ASAN+UBSAN `zdhunt_libfilezilla` relay harness;
UBSan fires `time.cpp:520` signed integer overflow.

Reachability note: libfilezilla is a shared toolkit lib — the finding matters
where a consumer parses attacker dates AND routes them into a sink; the sink
sweep shows the shipped FileZilla host does not.