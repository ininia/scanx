# Corrections found by running the real tools (2026-10-06)

`scanners.md` was written from documentation. Running every tool inside the
hardened scanner image (`--network none --read-only`, noexec `/tmp`, uid
65532) showed the following differences. The adapters follow **this** file.

| Tool | Documented | Verified behaviour | Consequence in scanX |
|---|---|---|---|
| Opengrep 1.30.0 | `--no-progress-bar` flag | Flag does **not** exist (`unknown option`). | Not used. |
| Opengrep 1.30.0 | — | Self-extracting binary: unpacks into `$XDG_CACHE_HOME/opengrep/<ver>` (default `~/.cache`). | Unpacked at image build into `/opt/scanx/home/.cache`; adapter sets `XDG_CACHE_HOME` to it, so runtime needs no writes there. |
| Opengrep 1.30.0 | — | Writes a log to `$HOME/.opengrep/semgrep.log`; fails on a read-only HOME. | Tools get a writable `HOME` on tmpfs. |
| Opengrep 1.30.0 | — | Crashes reading UTF-8 rule files when the locale is ASCII. | Image sets `LANG/LC_ALL=C.UTF-8`. |
| Opengrep 1.30.0 | — | Honors a repository `.semgrepignore` unless `--x-ignore-semgrepignore-files` is given. | Flag always passed (a repo must not hide files). |
| Opengrep 1.30.0 | — | JSON `extra.lines` contains the raw matched source line, including any secret on it. | Raw tool output is never stored; scanX snippets are masked for **all** categories. |
| OSV-Scanner 2.6.0 | Offline DB at `<cache>/osv-scanner/<Eco>/all.zip` | Looks in `<cache>/osv-scalibr/<Eco>/all.zip`; works with a read-only cache once present. | Image uses the `osv-scalibr` layout. |
| OSV-Scanner 2.6.0 | — | Exit 128 = no packages, and **no output file** is written. | Adapter treats a missing file as "no findings". |
| Gitleaks 8.30.1 | — | Values containing stop-words such as `fake`/`example` are ignored. | Fixtures mark FAKE in a comment, not in the value. |
| Gitleaks 8.30.1 | JSON fields UNVERIFIED | Verified: `RuleID, Description, StartLine, EndLine, StartColumn, EndColumn, Match, Secret, File, SymlinkFile, Commit, Entropy, Author, Email, Date, Message, Tags, Fingerprint`. With `--redact`, `Match`/`Secret` contain `REDACTED`. | Golden files in `testdata/scanner-outputs/gitleaks`. |
| Trivy 0.75.0 | JSON fields UNVERIFIED | Verified as documented; also `PkgIdentifier.PURL`, `CauseMetadata.StartLine`, `Status` (`FAIL`/`PASS`) on misconfigurations. | `PASS` misconfigurations are skipped. |
| Syft 1.54.0 | CycloneDX 1.6 | Emits CycloneDX **1.7**. | SBOM validation only checks `bomFormat`. |

All golden inputs are regenerated with `scripts/capture-golden.sh` (see header).
