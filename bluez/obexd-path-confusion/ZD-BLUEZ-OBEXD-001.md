# ZD-BLUEZ-OBEXD-001 — verify_path prefix-confusion opens the directory-discovery engine outside the OBEX root (obexd)

AI-exclusive finding · BlueZ 5.85 (fixture) · gate code source-verified against upstream master 2026-10-09

## TL;DR
obexd's path verifier is a prefix check:

```c
/* obexd/plugins/filesystem.c:90 */
int verify_path(const char *path)
{
    if (obex_option_symlinks()) return 0;          /* option = allow-all  */
    t = realpath(path, NULL);
    if (!g_str_has_prefix(t, obex_option_root_folder())) ret = -EPERM;
    ...
}
```
With root `/base/r`, the sibling directory `/base/rEVIL` **shares the prefix** →
`realpath()` returns it → `g_str_has_prefix("/base/rEVIL", "/base/r")` is TRUE
→ **rc=0, gate open**.

That rc=0 is then consumed by the **directory-discovery engine**:
`append_listing()` (`filesystem.c:~480`) `opendir()`s the path and emits every
entry's name/perm/size/mtime (`file_stat_line`) back over OBEX — folder-listing
is the FTP GET listing payload.

**Proven on this box** (real `filesystem.o` linked into a harness, real driver
function pointers captured via the plugin's own `filesystem_init()`):

```
verify_path("/tmp/gatebox-*/rootEVIL") rc=0  <-- with root "/tmp/gatebox-*/root"
folder.open("/tmp/gatebox-*/rootEVIL") emitted 331 bytes, contains "secret.txt"
   <-- DIRECTORY DISCOVERY OUTSIDE ROOT
```
Same run: outside-root path → correctly denied; symlink targets → correctly
denied; inside → allowed (differential controls).

A second, config-dependent hole in the same function: **`--symlinks` option
makes `verify_path` return 0 unconditionally** (allow-all), turning any
symlink inside the root into an open door. Proven: with the option on,
outside-root paths return rc=0.

## 1. Metadata
| Field            | Value                                                        |
|------------------|--------------------------------------------------------------|
| Title            | prefix-confusion in verify_path -> out-of-root dir listing   |
| Component        | BlueZ obexd `plugins/filesystem.c` (`verify_path` :90,       |
|                  | `append_listing` ~480, `folder_open` ~555)                   |
| Affected         | BlueZ 5.85 fixture; verify_path/listing source unchanged on  |
|                  | upstream master (fetched & diffed 2026-10-09)                |
| Fixed in         | NONE                                                         |
| CVE              | NONE assigned (checked NVD/OSV 2026-10-09)                   |
| CWE              | CWE-22 (path traversal / prefix confusion) -> CWE-200        |
|                  | (directory + metadata disclosure); option hole = CWE-284     |
| Severity         | 6.5-7.5 CONDITIONAL — flow reachability below; local daemon, |
|                  | peer-supplied path component after auth (OBEX FTP profile)   |
| Reporter         | seraphine AI agent (gate fixture)                            |
| First hit        | 2026-10-09                                                   |
| Build/flags      | gcc -O1 -g, real `filesystem.c` compiled -DOBEX_PLUGIN_      |
|                  | BUILTIN, glib/gio/dbus via pkg-config                        |

## 2. Reachability (honest, per-flow)
- **Gate-level PROVEN**: `verify_path(sibling)==0` and sibling listing emits
  out-of-root contents (both executed, controls included).
- **Flow status**: how a path string pointing at the sibling reaches
  `verify_path`/`folder_open` in a stock daemon: `ftp_setpath`'s own
  `is_filename`+`verify_path` normally prevent *constructing* such a folder
  state with `..`. The reachable constructor is a **symlink inside the root**
  (allowed name, no `/`): `realpath` of `root/link -> /base/rEVIL` lands on
  the sibling and the prefix confusion accepts it. Precondition: a symlink
  exists in the shared OBEX folder (plausible in user folders) — NOT
  demonstrated end-to-end through a full obexd session; labelled FLOW-CANDIDATE.
- The `--symlinks` option hole is config-dependent by design; documented, not
  inflated.
- **Memory-corruption escalation path (CANDIDATE)**: a write primitive that
  shortens/corrupts the `root_folder` string widens every prefix match (root
  `/b` matches `/base/...`), converting this gate into unconditional allow
  without any symlink precondition — this is the intended next rung joining
  the decoder-write hunt to traversal.

## 3. Steps to reproduce
```sh
bash /home/box/BTHunt/orch/build_gate.sh     # compiles real filesystem.c -> .o
bash /home/box/BTHunt/orch/gate/run_gate.sh   # plants sandbox, builds, runs T1-T5
```
Observed (2026-10-09): T2 line `verify_path(.../rootEVIL) rc=0 <-- PREFIX
CONFUSION`; T5 line `SIBLING listing ... contains secret.txt: YES <-- DIRECTORY
DISCOVERY OUTSIDE ROOT`; controls inside/outside/symlink behave as intended.

## 4. Differential
| path                              | verify_path (symlinks OFF) | listing        |
|-----------------------------------|----------------------------|----------------|
| root/in.txt (inside)              | 0 (allow)                  | n/a            |
| outside/secret2.txt               | -EPERM (deny) ✓            | n/a            |
| **rootEVIL (sibling prefix)**     | **0 (allow) ✗**            | **331B emitted** |
| root/link (symlink -> outside)    | -EPERM (deny) ✓            | rejected ✓     |
| any outside path, symlinks ON     | 0 (allow, config)          | would emit     |

## 5. Fix (suggested)
```c
size_t rl = strlen(root = obex_option_root_folder());
if (strncmp(t, root, rl) != 0 || (t[rl] != '\0' && t[rl] != '/'))
    ret = -EPERM;                     /* segment-boundary prefix check */
```
plus: realpath+verify BEFORE opendir/open (see ZD-BLUEZ-OBEXD-002).

## 6. References
- `obexd/plugins/filesystem.c:90-110` verify_path; `~480-555` append_listing/folder_open
- `obexd/plugins/ftp.c:215-280` ftp_setpath (construction gates); `ftp_build_filename`/
  `is_valid_path` `ftp.c:320-360` (the `..` depth counter — correctly blocks raw `..`)
- Same-class prior: CVE-2017-1000250 (BlueBorne, bluetoothd SDP — different component);
  no prior advisory covers obexd verify_path (checked 2026-10-09)
- Harness: `/home/box/BTHunt/orch/gate/{gate_test.c,run_gate.sh}`, sandbox kept at
  `/tmp/gatebox-t5U7Cz`

## 7. Method note
Gate-first per the traversal recipe: map store -> consumers -> sanitizer ->
verifier -> sink order before any testing; harness drives the REAL plugin via
its own `filesystem_init()` registration (stub `obex_mime_type_driver_register`
captures the actual static callbacks), so no gate function is called
"directly" for the discovery proof — the listing goes through the registered
folder driver exactly as obexd invokes it.
