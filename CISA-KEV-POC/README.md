# CISA-KEV-POC — PoCs for recently-added KEV CVEs with no public PoC

Selected from CISA's **Known Exploited Vulnerabilities** catalog (feed
2026-10-16). Each was confirmed to have **no public PoC** in the
[nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) catalog OR in
individual verification (Exploit-DB / advisories / gists), then a PoC was built.

**Honesty policy (the same one the whole repo holds):** these are *real,
buildable* artifacts, but **none of them is a claimed live compromise of any
real system.** Verification level is stated per finding in an explicit
`VERIFIED vs HYPOTHESIZED` table. A "verified" row means proven by executed code,
real firmware/binary analysis, or official documentation on this box; a
"hypothesized" row means inferred and untested against the named product.

| CVE | Target | Class | PoC depth |
|---|---|---|---|
| [`CVE-2026-7273`](CVE-2026-7273-zyxel-gs1900-cgi-bof/) | Zyxel GS1900 series (48HPv2) | CWE-121 stack BOF in CGI → OS cmd | **RCE closed, then upgraded to CONTROLLED EXECUTION in the real MIPS binary under QEMU user-mode**: overflow clobbers saved `$ra` (SIGSEGV at injected markers); a NUL-free stack-pivot + ROP chain (libc addresses) yields a clean controlled `exit(0x41414141)` (=65) and a `write(2,…,"Segmentation fault"…)` marker — both observed via `qemu -strace`. Real-hardware reuse HYPOTHESIZED (qemu libc is un-ASLR'd); arbitrary code/shell not claimed. |
| [`CVE-2026-102490`](CVE-2026-102490-zammad-lpe/) | Zammad (packager.io DEB/RPM) | CWE-269 LPE: packaged services run as root and source app-user-writable `.profile.d`/`conf.d` files | Real pre-fix/post-fix differential executed in an unprivileged user-ns: attacker code runs `uid=0` pre-fix, `uid=33` post-fix. Fix = pkgr commit `89abf95`. |
| [`CVE-2026-83549`](CVE-2026-83549-sma1000-cmdi/) | SonicWall SMA1000 AMC | CWE-78 OS command injection (`sysCtrl.execCmsSnmpTrap` sed `e`-flag) | Runs end-to-end against our validated SMA1000 fixture (wsproxy SSRF → AMC 8188); command output returned in the XML-RPC response; negative controls pass. Endpoint third-party-documented (HYPOTHESIZED); no real appliance. |
| [`CVE-2026-84869`](CVE-2026-84869-screenconnect-privesc/) | ConnectWise ScreenConnect | CWE-862/CWE-269 missing-auth transfer+exec through live session (CVSS 9.9) | Root cause verified from official advisory; protocol model runs (pre/patch differential). No client binary → exact wire format hypothesized. |
| [`CVE-2026-96951`](CVE-2026-96951-winshell-cmdinject/) | Microsoft Windows Shell | CWE-77 cmd injection / MOTW security-feature bypass | LNK-artifact generator (structurally valid `[MS-SHLLINK]`) + parsing model; injection-split verified at grammar level. No live Windows execution. |

## Reproduce
Each subfolder has a runnable `poc/*.py` and a `REPORT.md` with the exact
invocation. Local self-tests (stub servers, parsing models, self-validating
harnesses) are included and have been run — see each report's verification table.

## Learn more / selection method
- Full shortlist methodology in the accompanying analysis: 126 KEV CVEs added
  in the last 120 days, intersected with an 11,261-CVE public-PoC index, then
  individually web-verified. See the `REPORT.md` in each folder for why no
  public PoC was found at selection time.