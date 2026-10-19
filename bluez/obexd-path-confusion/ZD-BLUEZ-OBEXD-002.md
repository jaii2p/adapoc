# ZD-BLUEZ-OBEXD-002 — filesystem_open truncates BEFORE verify_path: rejected write still destroys the outside target (obexd)

AI-exclusive finding · BlueZ 5.85 (fixture) · production flags confirmed at obex.c:710

## TL;DR
```c
/* obexd/plugins/filesystem.c:161 — filesystem_open */
fd = open(name, oflag, mode);        /* :169  <-- fires FIRST, follows symlinks */
if (fd < 0) return NULL;
if (fstat(fd, &stats) < 0) goto failed;
ret = verify_path(name);             /* :182  <-- the gate runs AFTER the open */
if (ret < 0) { *err = ret; goto failed; }   /* closes fd — but open already acted */
```
Production caller, `obex_put_stream_start` (`obexd/src/obex.c:710`):

```c
os->object = os->driver->open(filename, O_WRONLY | O_CREAT | O_TRUNC, ...);
```

So for an OBEX PUT whose target resolves (through a symlink with an
allowed name) outside the root: **the outside file is created/truncated at
open() time, then the transfer is rejected** — `open` returns NULL with
`-EPERM`, but the bytes are already gone.

**Proven on this box** (real `filesystem.o`, real registered `file` driver,
production flags, symlinks option OFF, full controls):

```
open returned NULL (err=-EPERM)          <-- gate REJECTED the write
outside victim size now: 0               <-- TRUNCATED ANYWAY
   <-- SIDE EFFECT BEFORE VERIFY
control: inside file opens normally      <-- differential clean
```

Reachability (honest): the wire name must be `is_filename`-clean (no `/`,
not `..` — e.g. an existing symlink name inside the shared folder
`root/filelink -> ../outside/secret2.txt`). FTP PUT / OPP PUT then build
`g_build_filename(folder, name)` exactly as tested. Precondition: a symlink
exists inside the OBEX root folder (or the `--symlinks` option is set, in
which case verify never rejects at all and the write FULLY lands).

## 1. Metadata
| Field            | Value                                                        |
|------------------|--------------------------------------------------------------|
| Title            | open(O_TRUNC) before verify_path -> destructive side effect  |
|                  | outside root despite rejected transfer                       |
| Component        | BlueZ obexd `plugins/filesystem.c` `filesystem_open` :161-190 |
| Affected         | BlueZ 5.85; same open-then-verify order on upstream master   |
|                  | (fetched 2026-10-09)                                         |
| Fixed in         | NONE                                                         |
| CVE              | NONE assigned (checked 2026-10-09)                           |
| CWE              | CWE-22 (traversal via symlink) + CWE-59 (symlink use) with   |
|                  | CWE-367-style check-after-use ordering; integrity impact     |
| Severity         | 5.9 MEDIUM (conditional on symlink-in-folder precondition) — |
|                  | CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N                |
| Reporter         | seraphine AI agent (gate fixture)                            |
| First hit        | 2026-10-09                                                   |
| Build/flags      | gcc -O1 -g, real filesystem.c (-DOBEX_PLUGIN_BUILTIN), glib   |

## 2. Description
`verify_path` after `open` cannot undo what the open already did:
- `O_TRUNC` zeroes the target file at open time (demonstrated);
- `O_CREAT` would create a new outside entry (same window);
- fstat/statvfs side effects are harmless, truncation is not.
`append_listing` has the same ordering (`opendir` :480 before `verify_path`
:490) but is non-destructive — its verify failure discards the listing, so it
is noted, not filed.

## 3. Steps to reproduce
```sh
bash /home/box/BTHunt/orch/build_gate.sh
bash /home/box/BTHunt/orch/gate/run_gate.sh
# T4 section: file.open(p_flink, O_WRONLY|O_TRUNC, ...) via real driver
# post-state printed by the script: victim content becomes empty
```

## 4. Differential
| input                                   | result                                    |
|-----------------------------------------|-------------------------------------------|
| inside file, O_RDONLY (control)         | object returned, contents read ✓          |
| symlink->outside, O_WRONLY\|O_TRUNC     | NULL/-EPERM **but victim truncated to 0** |
| same flow, symlinks option ON           | open succeeds AND write lands (config)    |
| symlink name that doesn't exist         | O_CREAT would create outside (same window)|

## 5. Impact
- Integrity: outside-root files inside the shared folder's reach can be
  zeroed (or created) by an unauthenticated OBEX peer *before* the transfer
  is denied — the error return lies about the side effect.
- Combined with OBEXD-001: the same symlink reachability that defeats
  `verify_path` by prefix also powers this destructive window.
- Not RCE; integrity-only, gated on symlink presence or `--symlinks`.

## 6. Fix (suggested)
```c
ret = verify_path(name);        /* FIRST — after realpath resolution */
if (ret < 0) { if (err) *err = ret; return NULL; }
fd = open(name, oflag, mode);   /* then open */
```
(or open with O_NONBLOCK + re-verify fd via fstat/proc-self-fd realpath
before truncating; never pass O_TRUNC before the gate).

## 7. References
- `obexd/plugins/filesystem.c:161-190` (open/fstat/verify order)
- `obexd/src/obex.c:706-712` (production flags O_WRONLY|O_CREAT|O_TRUNC)
- `obexd/plugins/ftp.c ftp_chkput` / `plugins/opp.c opp_chkput` (name gates
  that the symlink name legitimately passes)
- Prior-art check: no NVD record for this ordering (2026-10-09); closest
  same-class = local symlink-follow advisories in other daemons
- Harness: `/home/box/BTHunt/orch/gate/gate_test.c` (T4), sandbox
  `/tmp/gatebox-t5U7Cz`

## 8. Method note
Order-of-operations test built from the sink outward: planted victim with
known content, drove the REAL registered driver callback with the EXACT flags
production uses (obex.c:710), observed victim state after the rejected open.
Control path (inside file) proves the harness/driver wiring is sound.
