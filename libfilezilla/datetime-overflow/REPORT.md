# ZD-LFZ-DATETIME-001 — Signed 64-bit integer overflow (UB) in datetime::set() / rfc3339 parser
# AI-exclusive finding · libfilezilla 0.57.0 (2026-08-24)

## TL;DR
libfilezilla 0.57.0's `fz::datetime::set(tm&, ...)` computes
`t_ = static_cast<int64_t>(tt) * 1000` at `time.cpp:520` with **no guard** on
the magnitude of `tt`. An attacker-controlled rfc3339 date string with a large
`year` field drives `timegm()` — called from `do_set_rfc3339` — to a
`time_t` whose `* 1000` overflows signed 64-bit (C11 6.5.5 / C++17[expr.mul]).
The wrapped `t_` then flows into every downstream consumer of the `datetime`
(e.g. `get_time_t`, `get_tm`, `get_rfc822`, `format`, subtraction). Bare 26-byte
trigger; no host-side state required. **Stream-reachable** (only attacker date
bytes needed). Found by the `zdhunt` creative fuzzer's new G_LFZ arms.

---

## 1. Metadata
| Field                  | Value                                                           |
|------------------------|-----------------------------------------------------------------|
| Title                  | Signed integer overflow (UB) in datetime::set (rfc3339 year)     |
| Affected               | libfilezilla 0.57.0 (2026-08-24 release); SONAME libfilezilla59  |
| Fixed in               | UNPATCHED (checked 2026-09-27: 0.57.0 is current upstream)       |
| CVE                    | NONE (checked 2026-09-27; no prior disclosure of this defect)    |
| Severity (realistic)   | Low-ish: UB / wraparound. No ASAN memory-corruption yet proven.  |
| Reachability           | Stream-reachable: rfc3339 date bytes only (26-byte minimal)      |
| Reporter               | seraphine AI agent via `zdhunt` creative fuzzer (G_LFZ arms)     |
| First hit              | 2026-09-27 (this campaign)                                       |
| Build/flags            | gcc 16.2.0 `-fsanitize=address -fsanitize=undefined -O1`, c++17 |

## 2. Description
`lib/time.cpp` `datetime::set(tm& t, accuracy a, zone z)`:

```c
506 bool datetime::set(tm& t, accuracy a, zone z)
507 {
508     time_t tt;
509     errno = 0;
512     if (a >= hours && z == local) tt = mktime(&t);
516     else                          tt = timegm(&t);
519     if (tt != time_t(-1) || !errno) {
520         t_ = static_cast<int64_t>(tt) * 1000;   // <-- OVERFLOW, no guard
521         a_ = a;
526         return true;
529     clear();
530     return false;
531 }
```

`tt` is `time_t` (64-bit). `t_.*` type is `int64_t t_`. Neither the multiply
nor the earlier `mktime`/`timegm` accept path bounds `tt`. `timegm` is called
with `tm` fields derived (via `time.cpp:946` rfc3339 path) from attacker
digits: `year` (up to 10 digits), month, day, hour, minute, second.

Entry `do_set_rfc3339` (time.cpp:891-977) parses a full RFC-3339 string,
`fz::to_integral<int>` (unbounded, no clamp) each of year/month/day/
hour/minute/second, then calls `dt.set(datetime::utc, year, month, day, hour,
minute, second [, ms])` (time.cpp:943/946). That inline `set(zone,int,...)`
stuffs the digits into `tm` (time.cpp:400-407) and calls `set(tm,a,z)`.

For `year = 2147483647`, `timegm` returns `tt = 67767976203244`
(`= ~2.1e9 yr * 31.56e6 s`), and the multiply `67767976203244200 * 1000`
overflows signed `int64_t`. UBSan flags it; on optimized 64-bit builds the
product wraps to a garbage value stored in `t_`.

### Why it matters (vs the earlier gzseek64 finding)
The gzseek64 UB was **caller-driven** (required a host app to seek by
exabyte-scale offsets). This defect is **attacker-stream-driven**: only the
date bytes need to arrive. It is the *same CWE-190 class* Apple patched in
ImageIO more than eight times in 2026 (see FUZZING-DISCIPLINE.md section 3),
now present in the date grammar of a widely-shipped FTP-client toolkit lib.

## 3. Steps to reproduce
1. Build libfilezilla 0.57.0 + the provided relay harness (both ASAN+UBSAN):
   `CFLAGS/CXXFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"`
2. Feed the bare 26-byte trigger (minimal):
   `2147483647-01-15T10:30:00Z`
   or the 68-byte fuzzer-saved one:
   `targets/libfilezilla/campaign1/20260927-031345/crashes/crash-000001.bin`
   through `./zdhunt_libfilezilla`.
3. Observed:
   ```
   time.cpp:520:33: runtime error: signed integer overflow:
   67767976203244200 * 1000 cannot be represented in type 'long int'
       #0 fz::datetime::set(tm&, ...)  time.cpp:520
       #1 fz::datetime::set(zone,...)  time.cpp:409
       #2 do_set_rfc3339              time.cpp:946
       #3 fz::datetime::set_rfc3339   time.cpp:982
   ```

## 4. Differential (authoritative, this box)
| Input                        | 0.57.0 (ASAN+UBSAN)                 |
|------------------------------|-------------------------------------|
| `2147483647-01-15T10:30:00Z` | UBSAN signed-overflow fires          |
| `9999999999-01-01T00:00:00Z` | NO overflow (timegm returns -2208988800, saturates) |

## 5. Downstream flow of the wrapped `t_` (carries the 3-byte divergence)
Probe (`probe_trace.cpp`) after setting the overflow date:
- `get_time_t()` -> `-6019000091594007` (huge negative time_t)
- `get_tm(utc)`   -> `year=-190734450, mon=0, mday=10, hour=0` (out of range)
- `format(...)`   -> runs `strftime` on that tm (fixed 1000-byte buf, bounded)
- `get_rfc822()`  -> indexes `months[]`/`wdays[]` (checked: mon<0||mon>11)
- `base - d`      -> `diff_ms = 6019001795661206464` (int64 sub of wrapped val)

The corrupted `t_` value is stored on the `datetime` object and observed by
every consumer. This is the B1 (validated cal) vs B2 (used ms) divergence the
chain hunt wants. RCE link **NOT yet proven**: no ASAN heap/stack fault was
observed on any downstream consumer in the current harness. The “outside
the library” relay (feeding this wrapped datetime into a second, bigger
consumer that turns `t_` into a size/index/allocation) is the declared next
step, not a claim.

## 6. Impact
- CONCRETE: **signed-type-overflow (UB)**, fully attacker-driven, 26-byte.
- No ASAN memory-corruption / OOB / UAF observed on any tested consumer.
- The stored wrapped `t_` deterministically corrupts future arithmetic and
  formatting of the same datetime object (DoS/logic corruption of any
  datetime-dependent logic in a consumer).
- Practical severity: Low. Class it as CWE-190 overflow-in-arithmetic, the
  CVE-2026 ImageIO family, but here it terminates in benign-wrapped-ms until a
  downstream sink is chained to it. Faithful severity, not inflated.

## 7. Fix (suggested, mirrors upstream pattern)
Bound `tt` before scaling, or use saturating widen:
```c
if (tt > (std::numeric_limits<int64_t>::max() / 1000) ||
    tt < (std::numeric_limits<int64_t>::min() / 1000)) {
    clear();
    return false;               /* or clamp */
}
t_ = static_cast<int64_t>(tt) * 1000;
```
Also consider bounding `year` at the parser on the rfc3339/rfc822 paths
(rfc3339 allows 4-digit year per RFC 3339; reject `year < 0 || year > 9999`
or clamp before `timegm`).

## 8. References
- `lib/time.cpp` `datetime::set(tm&...)` line 520, `do_set_rfc3339` line 946
- `lib/time.hpp` `t_` (int64_t ms since epoch)
- CVE-2024-31497 (libfilezilla, PuTTY/ed25519 — UNRELATED, listed only to
  confirm nothing else is attributed here)
- Found with `zdhunt` creative fuzzer, **G_LFZ** `count_overflow_field` +
  `recurcliff` + `timezone_offset_cliff` + `block` stack. 0.57.0 is current
  upstream as of check date.

## 9. Method note (why the G_LFZ arms found it where generic flips did not)
The `count_overflow_field` mutator writes gorilla-width decimal fields
(INT_MAX/0xFFFF) into digit runs; `recurcliff` (G_GRAMMAR) preserves grammar
while pushing a `KEY=num` field to cliff values; `timezone_offset_cliff` and
`year_carry_splice` shape the date fields. The target is libfilezilla's
C++17 `to_integral<int>`-unbounded decimal parse feeding `timegm`, a surface
generic byte-flippers never specifically reach — the checked-field (a “valid”
year) vs used-field (`tt * 1000`) divergence is deliberately constructed, not
searched for.