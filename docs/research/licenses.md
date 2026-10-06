# Scanner licenses: commercial / SaaS risk (T-0011)

Status as of 2026-10-06. This is engineering research, not legal advice. Have counsel
review the "high" rows before any commercial or SaaS launch.

## How to read "SaaS/commercial risk"

- **none**: permissive license (MIT, Apache-2.0, BSD, MPL-2.0, CC0/public domain).
- **low**: attribution or copyleft obligations only. Examples: LGPL/GPL/AGPL scanners run
  as separate, unmodified processes in their own containers (aggregation, not linking);
  data under CC-BY/CC-BY-SA, which needs attribution. Obligations: ship license texts and
  source offers with distributed images, publish modifications (AGPL also applies to
  network use), and show attribution and notices in the UI or docs.
- **high**: the license restricts commercial use, SaaS use or "competing" use, or is
  non-OSI or non-commercial. Do not ship or enable by default.

scanX is AGPL-3.0, so pairing it with copyleft tools raises no compatibility problem.
If scanX is ever offered under a proprietary or dual license, re-check the AGPL/GPL rows.
Running them as separate programs is still generally fine, but any *modified* AGPL tool
(TruffleHog, Trail of Bits rules) used over a network must have its source offered.

## Table

| Tool | Engine license | Rules / DB license | SaaS/commercial risk | Notes | Source |
|---|---|---|---|---|---|
| Opengrep | LGPL-2.1 | No bundled rules. Rule set chosen by scanX (see recommendation). | none / low | Run as a separate binary. No telemetry or version check per source. | https://github.com/opengrep/opengrep , https://github.com/opengrep/opengrep/blob/main/src/osemgrep/cli_scan/Scan_CLI.ml |
| Semgrep CE | LGPL-2.1 | Registry/`semgrep-rules`: **Semgrep Rules License v1.0**: "does not allow you to distribute the rules, or to make them available to others as a service" | engine: low; **registry rules: high** | Engine is fine. Never bundle or fetch `p/*`, `r/*` or `--config auto`. Metrics must be off. | https://github.com/semgrep/semgrep , https://semgrep.dev/legal/rules-license , https://github.com/semgrep/semgrep-rules/blob/develop/LICENSE |
| opengrep-rules (`opengrep/opengrep-rules`) | n/a | **Commons Clause + LGPL-2.1**. Archived. "for research, testing & benchmarking". | **high** | Commons Clause forbids selling a service whose value derives from the software | https://github.com/opengrep/opengrep-rules/blob/main/LICENSE |
| GitLab sast-rules | n/a | Root LICENSE is MIT. Legacy top-level language dirs carry a per-file header: MIT (GitLab), Apache-2.0 (gosec/Bandit-derived), and so on. `rules/lgpl/` is LGPL-3.0. **`rules/gitlab/` is the GitLab EE license.** **`rules/lgpl-cc/` is LGPL + Commons Clause.** Docs are CC-BY-SA-4.0. | none (MIT/Apache legacy files); low (`rules/lgpl`); **high (`rules/gitlab`, `rules/lgpl-cc`)** | The EE license requires a GitLab subscription for production use and forbids distribution. Filter every file by its header. | https://gitlab.com/gitlab-org/security-products/sast-rules/-/blob/main/LICENSE , https://gitlab.com/gitlab-org/security-products/sast-rules/-/blob/main/rules/gitlab/LICENSE , https://gitlab.com/gitlab-org/security-products/sast-rules/-/blob/main/rules/lgpl-cc/LICENSE |
| Trail of Bits semgrep-rules | n/a | AGPL-3.0 | low | Compatible with AGPL scanX | https://github.com/trailofbits/semgrep-rules |
| 0xdea / elttam / dgryski / federicodotta / AikidoSec / apiiro rules | n/a | MIT | none | | https://github.com/0xdea/semgrep-rules , https://github.com/elttam/semgrep-rules , https://github.com/dgryski/semgrep-go , https://github.com/federicodotta/semgrep-rules , https://github.com/AikidoSec/opengrep-rules , https://github.com/apiiro/malicious-code-ruleset |
| mindedsecurity android rules | n/a | GPL-3.0 | low | | https://github.com/mindedsecurity/semgrep-rules-android-security |
| Decurity smart-contract rules | n/a | **CC-BY-NC-SA-4.0** | **high** | Non-commercial | https://github.com/Decurity/semgrep-smart-contracts |
| gosec | Apache-2.0 | Built in (Apache-2.0) | none | | https://github.com/securego/gosec |
| Bandit | Apache-2.0 | Built in | none | | https://github.com/PyCQA/bandit |
| Psalm | MIT | Built in (taint stubs) | none | Executes `vendor/autoload.php`; see scanners.md | https://github.com/vimeo/psalm |
| PHPStan | MIT | Built in | none | | https://github.com/phpstan/phpstan |
| njsscan | LGPL-3.0 | Rules in repo (LGPL-3.0). Bundles Semgrep CE (LGPL-2.1). | low | | https://github.com/ajinabraham/njsscan |
| mobsfscan | LGPL-3.0 | Rules in repo | low | | https://github.com/MobSF/mobsfscan |
| ESLint + eslint-plugin-security | MIT / Apache-2.0 | Plugin rules Apache-2.0. SARIF formatter MIT. | none | | https://github.com/eslint/eslint , https://github.com/eslint-community/eslint-plugin-security , https://registry.npmjs.org/@microsoft/eslint-formatter-sarif |
| **Brakeman** | **Brakeman Public Use License (Synopsys)**. Not OSI. | Built in | **high** | Commercial use, including "commercial managed/Software-as-a-Service services" and "component of a value-added service/product", needs a paid license | https://github.com/presidentbeef/brakeman/blob/main/LICENSE.md , https://rubygems.org/gems/brakeman |
| SpotBugs | LGPL-2.1 | Built-in detectors | low | Needs bytecode | https://github.com/spotbugs/spotbugs |
| FindSecBugs | LGPL-3.0 | Built-in detectors | low | Needs bytecode | https://github.com/find-sec-bugs/find-sec-bugs |
| Security Code Scan | LGPL-3.0 | Built in | low | Unmaintained since 2022 | https://github.com/security-code-scan/security-code-scan |
| Gitleaks | MIT | Default config MIT | none | | https://github.com/gitleaks/gitleaks |
| Betterleaks | MIT | Built in | none | | https://github.com/betterleaks/betterleaks |
| TruffleHog | **AGPL-3.0** | Detectors in repo (AGPL-3.0) | low (AGPL scanX); medium if scanX goes proprietary | Run unmodified. Disable verification. Modifications must be published. | https://github.com/trufflesecurity/trufflehog/blob/main/LICENSE |
| Trivy | Apache-2.0 | trivy-db code Apache-2.0. trivy-checks MIT. DB data from GHSA (CC-BY-4.0), NVD, distro feeds, Go vulndb (CC-BY-4.0), RustSec (CC0), and others. Trivy docs mark every language source "Commercial Use ✅". | low | Show attribution and the NVD notice. Pin by digest (2026 supply-chain incident). | https://github.com/aquasecurity/trivy , https://github.com/aquasecurity/trivy-db , https://github.com/aquasecurity/trivy-checks , https://github.com/aquasecurity/trivy/blob/main/docs/guide/scanner/vulnerability.md |
| OSV-Scanner | Apache-2.0 | OSV.dev data under per-source licenses: GHSA, PyPA, Go and OSS-Fuzz are CC-BY-4.0; RustSec and Haskell are CC0; AlmaLinux and Drupal MIT; Bitnami and R Apache-2.0; **Ubuntu CC-BY-SA-4.0**; Erlang CC-BY-4.0 | low | Attribution needed. CC-BY-SA applies only to the data itself. | https://github.com/google/osv-scanner , https://github.com/google/osv.dev/blob/master/docs/data.md |
| Grype | Apache-2.0 | grype-db/vunnel code Apache-2.0. DB aggregates NVD, GHSA and distro feeds. No separate DB license published (**UNVERIFIED**). | low | | https://github.com/anchore/grype , https://github.com/anchore/grype-db , https://github.com/anchore/vunnel |
| Syft | Apache-2.0 | n/a | none | | https://github.com/anchore/syft |
| govulncheck | BSD-3-Clause | Go vuln DB entries CC-BY-4.0 | low (attribution) | | https://github.com/golang/vuln , https://github.com/golang/vulndb#license |
| GitHub Advisory DB (data) | n/a | CC-BY-4.0 | low (attribution) | | https://github.com/github/advisory-database/blob/main/LICENSE.md |
| NVD (data) | n/a | US Government public service. API Terms of Use ask apps to show "This product uses the NVD API but is not endorsed or certified by the NVD." | low | Applies when scanX or a tool calls the NVD API (e.g. Dependency-Check) | https://nvd.nist.gov/developers/terms-of-use |
| Checkov | Apache-2.0 | Policies in repo (Apache-2.0). Prisma Cloud data/severities are proprietary and only fetched with an API key. | none | Use `--skip-download`. Severities are null in OSS mode. | https://github.com/bridgecrewio/checkov |
| KICS | Apache-2.0 | Queries in repo (Apache-2.0) | none | Don't trust Docker Hub images (2026-04 compromise). Build from source. | https://github.com/Checkmarx/kics |
| Hadolint | GPL-3.0 | Built in. Embeds ShellCheck (GPL-3.0). | low | Separate process. Offer source with distributed images. | https://github.com/hadolint/hadolint/blob/master/LICENSE |
| ShellCheck | GPL-3.0 | Built in | low | Same as Hadolint | https://github.com/koalaman/shellcheck/blob/master/LICENSE |
| OWASP ZAP | Apache-2.0 | Add-ons are mostly Apache-2.0 (**UNVERIFIED** per add-on) | none | DAST; needs network | https://github.com/zaproxy/zaproxy |
| sonar-scanner CLI | LGPL-3.0 | **Analyzers (sonar-java, sonar-php, sonar-python, SonarJS, sonar-dotnet): SONAR Source-Available License v1.0**. Bans "Competing" use and AI ingestion of output. | **high** | Server also needed | https://github.com/SonarSource/sonar-scanner-cli , https://github.com/SonarSource/sonar-java/blob/master/LICENSE.txt |
| cppcheck | GPL-3.0 | Built in | low | | https://github.com/cppcheck-opensource/cppcheck |
| flawfinder | GPL-2.0 | Built in | low | | https://github.com/david-a-wheeler/flawfinder |
| cargo-audit / RustSec DB | Apache-2.0 OR MIT | CC0-1.0 | none | | https://github.com/rustsec/rustsec , https://github.com/rustsec/advisory-db/blob/main/LICENSE.txt |
| bundler-audit / ruby-advisory-db | GPL-3.0 | Public domain (contributor dedication) | low | | https://github.com/rubysec/bundler-audit , https://github.com/rubysec/ruby-advisory-db/blob/master/LICENSE.txt |
| zizmor / actionlint | MIT / MIT | Built in | none | | https://github.com/zizmorcore/zizmor , https://github.com/rhysd/actionlint |
| DevSkim | MIT | Built in | none | | https://github.com/microsoft/DevSkim |
| PMD | BSD-style | Built in | none | | https://github.com/pmd/pmd/blob/main/LICENSE |
| detekt, kube-linter, kubescape, detect-secrets, 2ms, Dependency-Check, osv-scalibr, retire.js | Apache-2.0 | Built in or own feeds. Retire.js repository data license **UNVERIFIED**. Kubescape regolibrary license **UNVERIFIED**. | none / low | | respective GitHub repos (see scanners.md) |
| tflint | MPL-2.0 | Plugins have their own licenses (**UNVERIFIED**) | none | | https://github.com/terraform-linters/tflint |
| ScanCode Toolkit | Apache-2.0 | License data CC-BY-4.0 | low (attribution) | | https://github.com/aboutcode-org/scancode-toolkit/blob/develop/NOTICE |
| **Bearer** | **Elastic License 2.0** | Built in | **high** | ELv2 bans providing the software as a managed service | https://github.com/Bearer/bearer/blob/main/LICENSE.txt |
| **CodeQL CLI** | **GitHub CodeQL Terms and Conditions** (not OSI) | Queries MIT, but the CLI terms govern use | **high** | Use is limited to OSS/academic research | https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md |
| **Safety DB** (pyupio) | n/a | **CC-BY-NC-4.0** | **high** | Use OSV/Trivy for Python instead | https://github.com/pyupio/safety-db/blob/master/LICENSE.txt |
| MegaLinter | AGPL-3.0 | Aggregates tools under various licenses | low | Integrate the tools directly instead | https://github.com/oxsecurity/megalinter |

### License red flags (summary)

1. **Brakeman**: SaaS and commercial use need a paid license from Synopsys/the maintainer.
   Exclude it from a commercial or SaaS scanX, or make it an opt-in that self-hosted,
   non-commercial users install and accept themselves. Ruby fallback: Opengrep Ruby rules
   plus bundler-audit/OSV for dependencies. GitLab's Ruby rules are only under
   `rules/lgpl-cc` (Commons Clause), so check Trail of Bits and elttam coverage instead.
2. **Semgrep Registry rules** (Semgrep Rules License v1.0): no distribution and no SaaS.
3. **opengrep-rules, amplify opengrep-rules, GitLab `rules/lgpl-cc/`**: Commons Clause.
   **GitLab `rules/gitlab/`**: GitLab EE license (proprietary).
4. **SonarQube analyzers** (SSAL), **Bearer** (ELv2), **CodeQL** (GitHub terms),
   **Safety DB** (CC-BY-NC), **Decurity rules** (CC-BY-NC-SA).
5. Copyleft engines (TruffleHog AGPL; Hadolint, ShellCheck and cppcheck GPL; LGPL engines)
   are acceptable as separate processes. Images that scanX distributes must include
   license texts and corresponding source or a source offer.
6. Vulnerability data needs **attribution**: GHSA, Go vulndb, OSV and ScanCode data are
   CC-BY-4.0; Ubuntu notices are CC-BY-SA-4.0; NVD needs its notice. Add a "Data sources
   and attributions" page to the scanX UI and docs.

## Recommendation: default SAST rule set

Decision context: "Opengrep + OSI-licensed rules by default, Semgrep CE engine optional".

1. **Default bundle (shipped in the scanX Opengrep image, pinned by commit, with license
   files and an attribution manifest)**:
   - GitLab `sast-rules`:
     - Take the legacy top-level directories `c/ csharp/ go/ java/ javascript/ python/ scala/`,
       keeping only files whose header says MIT or Apache-2.0.
     - Take `rules/lgpl/**` (LGPL-3.0: Java, JS, Kotlin, Objective-C, Swift).
     - **Leave out `rules/gitlab/**`.** It is under the GitLab EE license: production use
       needs a subscription, and distribution is forbidden.
     - **Leave out `rules/lgpl-cc/**`.** It carries the Commons Clause, and it is where
       GitLab's PHP and Ruby rules live.

     This is still the broadest OSI base: C, C#, Go, Java, JS/TS, Python, Scala, Kotlin
     and Swift, with CWE metadata.
   - Trail of Bits `semgrep-rules` (AGPL-3.0). Compatible with AGPL scanX and high
     quality. Record the AGPL in the attribution manifest.
   - 0xdea (C/C++), elttam, dgryski/semgrep-go, federicodotta (Java/Kotlin), AikidoSec,
     apiiro (malicious code). All MIT.
   - njsscan and mobsfscan run as their own scanners (LGPL-3.0). Their rule files can
     also be fed to Opengrep.
2. **Build-time license gate**: a CI step that walks every rule file and fails on
   "Commons Clause", "Semgrep Rules License", "Enterprise Edition", "NonCommercial", or a
   missing or unknown license header. Write a `RULES-LICENSES.json` manifest (rule id, source repo, commit,
   SPDX id).
3. **Never** use `--config auto`, `p/...` or `r/...` registry references with either
   engine. They need network and pull Semgrep-Rules-License content. Opengrep runs with no
   telemetry. If Semgrep CE is enabled, force `--metrics=off` and
   `SEMGREP_ENABLE_VERSION_CHECK=0`.
4. **Semgrep CE optional engine**: use the same local OSI rule bundle. Semgrep Registry
   rules may be allowed only as a user-supplied "bring your own rules" mount in
   self-hosted, internal-use deployments, with a UI warning that the Semgrep Rules
   License forbids use in a service offered to others. They must never be enabled in
   scanX SaaS.
5. **Taint depth**: run Opengrep with `--taint-intrafile`. Add Psalm `--taint-analysis`
   for PHP, gosec for Go, Bandit for Python, and njsscan for Node to cover gaps in the
   rule set.
6. **Coverage gaps to track**:
   - Ruby: Brakeman is excluded and the GitLab Ruby rules are Commons Clause.
   - PHP: GitLab's PHP rules are Commons Clause. Psalm taint fills part of the gap.
   - Dart.
   - Swift: only GitLab `rules/lgpl` and mobsfscan cover it.

   Plan scanX-owned rules under AGPL or MIT for these.
