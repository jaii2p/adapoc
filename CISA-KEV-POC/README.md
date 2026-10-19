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
| [`CVE-2026-7273`](CVE-2026-7273-zyxel-gs1900-cgi-bof/) | Zyxel GS1900 series (48HPv2) | CWE-121 stack BOF in CGI → OS cmd | **From the real firmware**: `dispatcher.cgi` (MIPS BE) extracted, overflow offsets + param names verified; HTTP PoC + stub pass. On-device RCE hypothesized. |
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