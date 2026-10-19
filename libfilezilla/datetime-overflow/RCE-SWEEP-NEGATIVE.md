# ZD-LFZ-DATETIME-001 — RCE-expansion hunt: authoritative memory-sink sweep
# Result: NO memory sink exists in libfilezilla 0.57.0 or in the FileZilla 3.71.0 host path reachable with this input. Defect stays logic-corruption / DoS. RCE relay NOT found (and is not reachable as the finding stands).

## 1. Goal
The finding's declared next step was: "feeding this wrapped datetime into a second, bigger
consumer that turns t_ into a size/index/allocation is the next step." This document runs that
hunt to ground. The task: find a memory sink that extends ZD-LFZ-DATETIME-001 into RCE.

## 2. What is attacker-controllable
`datetime::set(tm,...)` (time.cpp:520) stores `t_ = (int64_t)tt * 1000` with NO clamp. An
rfc3339 string with year ~2^31 (`2147483647-01-15T10:30:00Z`, 26 bytes) wraps `t_` to
`-6019000091594007464`. Consumer-observable effects (measured):
- get_time_t()      -> -6019000091594007
- get_tm(utc)       -> tm_year=-190734450, mon=0, mday=10, wday=4, hour=0
- diff (base - d)   -> 6019001795661206464 ms
- duration.get_seconds() -> 6019001795661206
So the attacker fully controls a specific `int64_t t_` and the `tm` fields derived from it.

## 3. Decisive check (skill-mandated BEFORE any RCE rig): sweep EVERY public consumer
### 3a. In-library consumers of t_ / get_time_t / get_milliseconds (exhaustive grep)
| consumer                                  | memory behavior                          |
|-------------------------------------------|------------------------------------------|
| format(str,zone) / format(wstr,zone)      | strftime(buf, 999, ...) fixed 1000-byte  |bounded regardless of t_
| verify_format                             | strftime(buf, 4096,...) fixed 4096-byte  |bounded
| get_rfc822()                              | guards  wday<0||>6 || mon<0||>11 -> empty|no OOB into months[]/wdays[]
| get_tm(z)                                 | gmtime_r/localtime_r on zeroed tm{}      |glibc handles any time_t
| get_time_t() / get_milliseconds()         | pure integer; ms normalized [0,1000)     |(time.hpp:211-217)
| operator- / comparisons / std::sort       | pure int64 arithmetic                     |bounded logic
| local_filesys::set_modification_time      | times[1].tv_sec=t; tv_nsec=ms*1000000     |tv_nsec validated, ms in [0,1000)
| file.cpp:555 utimes same                  | same                                     |bounded
| process/socket/mutex/util timeouts        | clamped_cast<DWORD>/int, Sleep/poll/ts   |bounded
| socket keepalive                          | static_cast<ULONG>                       |bounded
| tls_layer_impl gnutls cert times          | time_t to gnutls (error on invalid)      |no CPU/memory sink
| logger format                             | bounded strftime + sprintf                |bounded
**No consumer passes t_ (or a derived tm field) into reserve/alloc/new/[] as a size or index.**

### 3b. Authoritative ASAN+UBSAN run (this rig, fresh evidence)
`probe_sink_sweep` compiled against the pinned ASAN/UBSAN libfilezilla.so.59, run with the
26-byte trigger:
```
time.cpp:520:33: runtime error: signed integer overflow: 67767976203244200 * 1000 ...
[utimes]  set_modification_time(poisoned)     -> ok=1
[utimes2] set_modification_time(neg-wrapped)  -> ok=1  t=-98294685399 ms=0
[RESULT]  all consumers completed; NO ASAN/UBSAN memory fault observed.
```
All format families (utc+local, 22 specifiers), get_tm both zones, get_rfc822, arithmetic,
sort, duration view, AND the utimes path (the one consumer the original probe missed) are clean.
The ONLY report is the source overflow at time.cpp:520. EXIT=0.

## 4. Host-side relay check (FileZilla 3.71.0, the build shipping this library)
- FileZilla NEVER calls `fz::datetime::set_rfc3339` / `set_rfc822` (grep of engine + interface + commonui: zero hits). The rfc3339 huge-year form is not fed anywhere in the host.
- The network-reachable date path is MLSD `modify=`/`create=` (directorylistingparser.cpp:2622), but it uses `fz::datetime(s, zone)` — the COMPACT fixed-field `YYYYmmDD[[[[HH]MM]SS]sss]` parser, which is 4-digit-year by construction. No huge-year overflow reachable there.
- The Unix LIST parser bounds `year > 3000 -> false` (directorylistingparser.cpp:1030).
- MDTM response path (`ftp/list.cpp:159`) also routes to the same bounded compact/verify paths.
Even IF a date overflowed in the host, FileZilla's consumers of `entry.time` are the same
bounded set (format/get_tm/comparisons), so no memory join.

## 5. Verdict
ZD-LFZ-DATETIME-001 does NOT reach a memory sink in libfilezilla 0.57.0 or in any FileZilla
3.71.0 path reachable with its trigger. It terminates in benign-wrapped-ms signed-arithmetic:
CWE-190 overflow -> deterministic corruption of datetime-dependent LOGIC (sorts, comparisons,
filtering, formatting, arithmetic) in any consumer, i.e. spoofable server dates / logic DoS.
It is NOT RCE-extendable as found. Per the memory-corruption-research rule, do not inflate a
bounded-consumer logic bug to Medium/High on the strength of the UB alone.

## 6. What WOULD make it RCE (declared relay, not a claim)
A host consumer that satisfies BOTH:
  1. parses attacker-controlled bytes via set_rfc3339 / set_rfc822 (or passes a huge year
     through datetime::set), giving the wrapped t_; AND
  2. strings t_ (or a tm field derived from it) into a size, buffer index, table index, or
     allocation (reserve/alloc/new/[]).
No such consumer exists in libfilezilla 0.57.0 or FileZilla 3.71.0. If one is found in a
third-party consumer of libfilezilla, THIS is the precise sink contract to grep for.

## 7. Controls / build
- Trigger: `2147483647-01-15T10:30:00Z` (26B) through `./probe_sink_sweep`.
- Build: pinned libfilezilla-0.57.0, gcc 16.2.0, `-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`.
- Lib .so: targets/libfilezilla/src-0.57.0/lib/.libs/libfilezilla.so.59 (ASAN).
- Probe source: targets/libfilezilla/probe_sink_sweep.cpp (kept; binary probe_sink_sweep).

## 8. Sources
- lib/time.cpp:506-531 (datetime::set), 670-700 (format), 786-801 (get_rfc822), 702-709 (get_time_t), 711-759 (get_tm)
- lib/libfilezilla/time.hpp:211-217 (get_milliseconds normalized), 68-75 (compact string ctor)
- local_filesys.cpp:930-968 (set_modification_time tv_sec/tv_nsec), fsresult.hpp bool op
- filezilla-3.71.0/src/engine/directorylistingparser.cpp:1030 (year>3000 bound), 2622 (MLSD modify->datetime compact)
- filezilla-3.71.0/src/engine/ftp/list.cpp:159 (MDTM)
- Base finding: ZD-LFZ-DATETIME-001.md (+ prior probe_trace.cpp / probe_rce_depth.cpp)