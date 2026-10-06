# Scanner research (T-0011)

Status as of 2026-10-06. Versions/dates were taken from the GitHub releases API,
GitHub release redirects, Docker Hub, crates.io, RubyGems and proxy.golang.org on
that date. Anything not checked against a primary source is marked **UNVERIFIED**.

scanX runtime assumptions used throughout: one container per tool, `--network none`,
source at `/work/src` (read-only), output at `/work/out`, no build or install of repo
code. "Offline DB" means a DB baked into the image or mounted read-only, e.g. at
`/opt/<tool>-db`.

## Cross-cutting findings (read first)

1. **Repo-supplied config can change what a tool does, and sometimes runs code.**
   Several tools look for config inside the scanned directory or the working directory:
   `.gitleaks.toml`, `.semgrepignore`, `phpstan.neon`, `psalm.xml`, `eslint.config.js`,
   `config/brakeman.yml`, `.checkov.yaml`, `.shellcheckrc`, `.hadolint.yaml`.
   - The most dangerous cases execute repo code:
     - **Psalm** `require_once`s `<root>/vendor/autoload.php` if it exists.
     - **PHPStan** runs `bootstrapFiles` from an auto-discovered `phpstan.neon`.
     - **ESLint** configs are JavaScript.
     - **Checkov** `external-checks-dir` loads Python checks.
   - Mitigation: always run with the working directory outside `/work/src`, always pass
     an explicit scanX-owned config, and turn off config lookup where a flag exists.
     Details are in each section.
2. **Supply-chain incidents in 2026 hit scanner images directly.**
   - Trivy v0.69.4 binaries and the trivy-action/setup-trivy tags were malicious on
     2026-03-19, followed by malicious Docker Hub images v0.69.5/v0.69.6 on 2026-03-22
     (CVE-2026-33634).
     Sources: https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know ,
     https://safedep.io/trivy-teampcp-supply-chain-compromise/
   - Malicious images were pushed to the official `checkmarx/kics` Docker Hub repo on
     2026-04-22.
     Source: https://thehackernews.com/2026/04/malicious-kics-docker-images-and-vs.html
   - Docker Hub still shows `checkmarx/kics` last updated 2026-04-22 at tag v2.1.20,
     while GitHub has v2.2.0.
   - Recommendation: build scanX's own scanner images from checksum- and
     signature-verified release artifacts, pin everything by digest, and never use
     `:latest`.
3. **Tools that cannot work without network or a build** are covered in their own
   sections and summarised in licenses.md:
   - sonar-scanner and ZAP baseline cannot work without network.
   - SpotBugs/FindSecBugs and Security Code Scan cannot work without a build.
   - OSV-Scanner `--licenses` cannot work without network.
   - govulncheck source mode needs the module cache populated.

---

## Opengrep

- **Version**: v1.30.0 (2026-09-07). Source: https://github.com/opengrep/opengrep/releases/tag/v1.30.0
  - v1.30.0 removed the legacy flags `--oss-only` and `--diff-depth`.
- **Image**: no official container image. The opengrep GHCR org has no packages and
  Docker Hub has no `opengrep/opengrep`. Distribution is self-contained, Cosign-signed
  binaries (`install.sh`, release assets). Build our own image.
  Sources: https://github.com/orgs/opengrep/packages , https://github.com/opengrep/opengrep
- **License**: engine LGPL-2.1 (see licenses.md for rules).
- **Offline invocation**:
  ```sh
  opengrep scan --config /opt/rules --sarif-output=/work/out/opengrep.sarif \
    --json-output=/work/out/opengrep.json --no-progress-bar --quiet \
    --timeout 30 --max-target-bytes 5000000 --exclude 'node_modules' --exclude 'vendor' \
    --taint-intrafile /work/src
  ```
  - `-c/-f/--config` takes a file, a directory, a URL, `git+<url>`, or a registry name.
    For offline use, only point it at a local directory.
  - `--error` makes the run exit 1 on findings. Without it, exit 0 means it ran
    successfully. Other codes: 2 fatal, 7 missing/invalid config, 8 invalid language.
  - `--taint-intrafile` enables the improved inter-procedural taint mode.
    `--taint-interfile` is also present.
  - Other flags that exist: `--exclude`, `--include`, `--exclude-rule`, `--severity`,
    `--max-target-bytes`, `-j/--jobs`, `--max-memory`, `--timeout-threshold`.
  Source: https://github.com/opengrep/opengrep/blob/main/src/osemgrep/cli_scan/Scan_CLI.ml
- **Network**: none needed with local rules.
  - The source states "Opengrep never contacts a server to compare versions".
    `--disable-version-check` is accepted but has no effect.
  - The scan CLI has no `--metrics` flag.
  - `--config auto` and `p/...` registry names would contact the Semgrep Registry.
    Do not use them: network is needed, and those rules carry the Semgrep Rules License.
  Source: Scan_CLI.ml (o_version_check, o_config).
- **Parsing**: SARIF 2.1.0, same shape as Semgrep.
  - `runs[].results[].ruleId` is the rule id.
  - Severity is in `level` (error/warning/note, from rule severity ERROR/WARNING/INFO).
  - CWE/OWASP appear as `rules[].properties.tags` strings such as `"CWE-89: ..."`, copied
    from rule `metadata.cwe`.
  - JSON: `results[].check_id`, `path`, `start.line`/`end.line`, `extra.severity`,
    `extra.metadata.cwe` (string or list), `extra.metadata.confidence`, `extra.fingerprint`.
  - (Field names follow the Semgrep JSON schema that Opengrep forked. Check against a
    sample run.)

## Semgrep CE (engine)

- **Version**: v1.179.0 (2026-10-02). Source: https://github.com/semgrep/semgrep/releases
- **Image**: `semgrep/semgrep` on Docker Hub (also `returntocorp/semgrep`) and
  `ghcr.io/semgrep/semgrep`.
  Sources: https://hub.docker.com/r/semgrep/semgrep , https://github.com/orgs/semgrep/packages
- **License**: engine LGPL-2.1. Registry rules (`semgrep/semgrep-rules`) are under the
  **Semgrep Rules License v1.0**, which forbids distributing the rules or making them
  available to others as a service. See licenses.md.
  Sources: https://github.com/semgrep/semgrep , https://semgrep.dev/legal/rules-license
- **Offline invocation**:
  ```sh
  SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  semgrep scan --metrics=off --disable-version-check --config /opt/rules \
    --sarif-output=/work/out/semgrep.sarif --json-output=/work/out/semgrep.json \
    --exclude vendor --timeout 30 /work/src
  ```
  - `--metrics` takes auto (default), on or off. With `auto`, metrics are sent when rules
    are pulled from the registry or when logged in.
  - `--config auto` sends the project URL to the registry and enables metrics.
  - Exit codes: 0 ok; 1 findings (only with `--error`); 2 fatal; 3 parse error (with
    `--strict`); 4 invalid pattern; 5 unparsable YAML; 7 invalid rule; 8 unknown
    language; 13 invalid API key.
  Source: https://docs.semgrep.dev/cli-reference
- **Network**: none with local rules and metrics off.
- **Parsing**: same as Opengrep.
  - Quirk: Semgrep CE redacts some JSON fields (matched-line text, `extra.lines` =
    "requires login") unless logged in. Read the snippet from the source file instead.
    Source: comment in https://github.com/ajinabraham/libsast/blob/master/libsast/core_sgrep/helpers.py

### OSI-licensed / usable rule sets (instead of the Semgrep Registry)

| Rule set | License | Notes | Source |
|---|---|---|---|
| GitLab `sast-rules` (v2.10.1, 2026-09-21) | Mixed, by directory. The root LICENSE is MIT for content outside special directories. | **Usable**:<br>- Legacy top-level dirs `c/ csharp/ go/ java/ javascript/ python/ scala/`. Each file carries a header such as "License: MIT (c) GitLab Inc." or "License: Apache 2.0 (c) gosec". Filter by header.<br>- `rules/lgpl/` (LGPL-3.0: java, javascript, kotlin, oc, swift).<br><br>**NOT usable**:<br>- `rules/gitlab/` is under the **GitLab EE license**: production use needs a GitLab subscription, and distribution is forbidden.<br>- `rules/lgpl-cc/` is **LGPL + Commons Clause** (java, javascript, php, python, ruby, yaml, properties).<br><br>Rules are mapped to Bandit/gosec/FindSecBugs/ESLint ids and carry CWE metadata. | https://gitlab.com/gitlab-org/security-products/sast-rules , root LICENSE, `rules/gitlab/LICENSE`, `rules/lgpl-cc/LICENSE`, `rules/lgpl/LICENSE` |
| Trail of Bits `semgrep-rules` | AGPL-3.0 | High-quality rules for Go, Python, C, Rust, Solidity and others. AGPL is compatible with AGPL scanX. Rules shipped inside scanX must keep the AGPL. | https://github.com/trailofbits/semgrep-rules |
| 0xdea `semgrep-rules` | MIT | C/C++ vulnerability hunting | https://github.com/0xdea/semgrep-rules |
| elttam `semgrep-rules` | MIT | Mixed languages, audit-style | https://github.com/elttam/semgrep-rules |
| dgryski `semgrep-go` | MIT | Go | https://github.com/dgryski/semgrep-go |
| federicodotta `semgrep-rules` | MIT | Java/Kotlin audit rules | https://github.com/federicodotta/semgrep-rules |
| AikidoSec `opengrep-rules` | MIT | Small (7 commits). GitHub workflow prompt injection, npm publishing. | https://github.com/AikidoSec/opengrep-rules |
| apiiro `malicious-code-ruleset` | MIT | Malicious-code detection | https://github.com/apiiro/malicious-code-ruleset |
| njsscan / mobsfscan bundled rules | LGPL-3.0 | Node.js and mobile (Android/iOS) rules in Semgrep format | https://github.com/ajinabraham/njsscan , https://github.com/MobSF/mobsfscan |
| mindedsecurity `semgrep-rules-android-security` | GPL-3.0 | Android (OWASP MASTG) | https://github.com/mindedsecurity/semgrep-rules-android-security |
| NOT usable: `opengrep/opengrep-rules` | Commons Clause + LGPL-2.1 (fork of old semgrep-rules) | **Archived.** README says "intended for research, testing & benchmarking". The Commons Clause forbids selling. | https://github.com/opengrep/opengrep-rules |
| NOT usable: `amplify-security/opengrep-rules` | Commons Clause | Same problem | https://github.com/amplify-security/opengrep-rules |
| NOT usable: Decurity `semgrep-smart-contracts` | CC-BY-NC-SA-4.0 | Non-commercial only | https://github.com/Decurity/semgrep-smart-contracts |
| NOT usable: `semgrep/semgrep-rules` | Semgrep Rules License v1.0 | No SaaS, no redistribution | https://semgrep.dev/legal/rules-license |

## gosec

- **Version**: v2.29.0 (2026-08-26). Source: https://github.com/securego/gosec/releases
- **Image**: `securego/gosec` (Docker Hub), `ghcr.io/securego/gosec`.
  Source: https://github.com/securego/gosec#readme
- **License**: Apache-2.0. Rules are built into the binary.
- **Offline invocation**:
  ```sh
  cd /work/src && GOFLAGS='-mod=readonly -buildvcs=false' GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 \
  gosec -no-fail -fmt sarif -out /work/out/gosec.sarif -exclude-generated \
    -exclude-dir=vendor -exclude-dir=testdata ./...
  ```
  - `-fmt` accepts text, json, yaml, csv, junit-xml, html, sonarqube, golint, sarif.
  - `-stdout` prints to stdout in addition to writing `-out`.
  - `-no-fail` forces exit 0.
  - `-severity` and `-confidence` filter results.
  - `-tests` includes `_test.go` files.
  - `-track-suppressions` records `#nosec` usage (JSON/SARIF only).
  Source: README.
- **Network**: gosec loads packages through Go modules (`go list`). If dependencies are
  missing, the README says to run `go mod download`. With `--network none` and no module
  cache, type information for third-party packages is missing. gosec still analyses
  the repo's own code but reports load errors.
  - Options: pre-populate a module cache (impossible without network for arbitrary repos),
    accept degraded results, or use vendored modules when `vendor/` exists
    (`GOFLAGS=-mod=vendor`).
  - Note: the `GOFLAGS`/`GOPROXY` combination above is a scanX suggestion (**UNVERIFIED**
    against gosec docs).
- **Parsing**: SARIF 2.1.0 with rules G101..G60x.
  - Every rule maps to a CWE ("CWE Mapping" section). SARIF carries `taxa`/relationships
    to CWE.
  - JSON: `Issues[].{severity, confidence, cwe{id,url}, rule_id, details, file, line, column, nosec}`.
    Field names are from gosec's JSON report (**UNVERIFIED** against current output).
  - `line` can be a range "12-14".

## Bandit

- **Version**: 1.9.4 (2026-02-25). Source: https://github.com/PyCQA/bandit/releases
- **Image**: `ghcr.io/pycqa/bandit/bandit`. Source: https://github.com/orgs/PyCQA/packages
- **License**: Apache-2.0.
- **Offline invocation**:
  ```sh
  bandit -r /work/src -f sarif -o /work/out/bandit.sarif --exit-zero -q \
    -x '/work/src/.venv,/work/src/node_modules,/work/src/tests'
  ```
  - The SARIF formatter is built in, but needs the `bandit[sarif]` extra (`sarif-om`,
    `jschema-to-python`). JSON needs no extra.
  - Flags: `-l/-ll/-lll` (severity), `-i/-ii/-iii` (confidence), `--severity-level`,
    `--confidence-level`, `-c` config, `--ini`, `-b` baseline, `--exit-zero`,
    `--ignore-nosec`.
  - Exit 1 when issues are found, unless `--exit-zero` is given.
  Sources: https://github.com/PyCQA/bandit/blob/main/bandit/cli/main.py ,
  https://github.com/PyCQA/bandit/blob/main/setup.cfg ,
  https://bandit.readthedocs.io/en/latest/start.html
- **Network**: none.
- **Parsing**: JSON `results[].{test_id (B101..), test_name, issue_severity, issue_confidence, issue_cwe{id,link}, filename, line_number, line_range, col_offset}`.
  SARIF puts severity/confidence in result `properties`.
  (JSON field names: **UNVERIFIED** against the 1.9.4 sample.)

## Psalm (taint analysis)

- **Version**: 6.19.1 (2026-09-29). Source: https://github.com/vimeo/psalm/releases
- **Image**: no official image (none on Docker Hub; vimeo has no GHCR packages). Build
  our own image from the PHAR or Composer.
- **License**: MIT.
- **Offline invocation**: we generate the config. Never use the repo's `psalm.xml`, and
  never run with the working directory or `--root` inside `/work/src`.
  ```sh
  mkdir -p /tmp/psalm && cd /tmp/psalm   # scanX writes psalm.xml here: <projectFiles><directory name="/work/src"/>, ignoreFiles vendor
  psalm -c /tmp/psalm/psalm.xml --taint-analysis --report=/work/out/psalm.sarif \
    --no-progress --no-cache --threads=4 --no-suggestions --php-version=8.3
  ```
  - `--report=PATH` chooses the format from the file extension. Supported: sarif, json,
    xml, junit, checkstyle, sonarqube, codeclimate, and others.
  - Exit codes: 0 means no issues, 1 means Psalm failed to run, 2 means issues found,
    anything else is an internal error.
  - "When taint analysis is enabled, no other analysis is performed."
  Sources: https://github.com/vimeo/psalm/blob/6.x/docs/security_analysis/index.md ,
  https://github.com/vimeo/psalm/blob/6.x/src/Psalm/Internal/Cli/Psalm.php ,
  https://github.com/vimeo/psalm/blob/6.x/docs/running_psalm/command_line_usage.md
- **Security note (important)**:
  - `CliUtils::requireAutoloaders` does `require_once` on `<cwd or --root>/vendor/autoload.php`
    if that file exists. That executes repo code when `vendor/` is committed.
  - If a `composer.json` exists without an autoloader, Psalm exits 1.
  - Run from an empty directory.
  - Never enable `<plugins>` from the repo.
  Source: https://github.com/vimeo/psalm/blob/6.x/src/Psalm/Internal/CliUtils.php
- **Network**: none. `--shepherd` would upload to shepherd.dev, so never pass it.
- **Parsing**: SARIF from SarifReport.
  - JSON report fields: `type` (issue type, e.g. TaintedSql), `severity`, `file_path`,
    `line_from`, `taint_trace` (**UNVERIFIED**).
  - No CWE field. Map `Tainted*` issue types to CWEs yourself (TaintedSql to CWE-89,
    TaintedHtml to CWE-79, and so on).

## PHPStan

- **Version**: 2.3.0 (2026-10-06). Source: https://github.com/phpstan/phpstan/releases
- **Image**: `ghcr.io/phpstan/phpstan`. The Docker Hub `phpstan/phpstan` is stale (2021).
  Source: https://github.com/orgs/phpstan/packages
- **License**: MIT.
- **Offline invocation**:
  ```sh
  cd /tmp/phpstan && phpstan analyse -c /tmp/phpstan/scanx.neon --error-format=json \
    --no-progress --memory-limit=2G /work/src > /work/out/phpstan.json
  ```
  - No SARIF formatter. Built-in formats: table, raw, checkstyle, json, prettyJson, junit,
    github, gitlab, teamcity.
  - Output goes to stdout, so redirect it.
  - Exit code is non-zero when errors are found.
  Sources: https://github.com/phpstan/phpstan/blob/2.1.x/website/src/user-guide/output-format.md ,
  https://github.com/phpstan/phpstan/blob/2.1.x/website/src/user-guide/command-line-usage.md
- **Security note**: PHPStan auto-discovers `phpstan.neon`/`phpstan.neon.dist` in the
  working directory. `bootstrapFiles` and `--autoload-file` are `require_once`d, which
  executes code. Use our own config outside `/work/src`.
  Source: https://github.com/phpstan/phpstan-src/blob/2.1.x/src/Command/CommandHelper.php
- **Network**: none.
- **Value**: PHPStan is a type checker, not a security scanner. Use it only as an optional
  quality signal. Psalm taint plus Opengrep PHP rules are the security path.
- **Parsing**: JSON `files{path:{messages[{message,line,ignorable,identifier}]}}`. No
  severity and no CWE (**UNVERIFIED** field list).

## njsscan

- **Version**: 1.0.1 (2026-09-21). Source: https://github.com/ajinabraham/njsscan/releases
- **Image**: `opensecurity/njsscan` (Docker Hub, updated 2026-09-21).
- **License**: LGPL-3.0. Rules are in the same repo. It depends on `semgrep==1.172.0`
  (LGPL-2.1 engine) and libsast.
  Sources: https://github.com/ajinabraham/njsscan/blob/master/setup.py ,
  https://github.com/ajinabraham/njsscan
- **Offline invocation**:
  ```sh
  njsscan --sarif -o /work/out/njsscan.sarif /work/src   # add -w/--exit-warning for non-zero on warnings
  ```
  Other output options: `--json`, `--sonarqube`, `--defectdojo`, `--gitlab-sast`, `--html`.
  `-c` sets the path to the `.njsscan` config. `--missing-controls` turns on extra checks.
  Source: README usage block.
- **Network**: none. libsast invokes `semgrep scan --metrics=off --disable-version-check`.
  It does not run on Windows hosts, which does not matter inside Linux containers.
  Source: https://github.com/ajinabraham/libsast/blob/master/libsast/core_sgrep/helpers.py
- **Parsing**: JSON `nodejs{rule_id:{files[{file_path,match_lines,match_string}], metadata{cwe, owasp-web, severity, description}}}`.
  CWE is a full string, e.g. "CWE-89: ...". Example in README.

## ESLint + eslint-plugin-security

- **Versions**:
  - ESLint v10.12.0 (2026-10-02)
  - eslint-plugin-security v4.2.0 (2026-10-01)
  - `@microsoft/eslint-formatter-sarif` 3.1.0 (MIT)
  - typescript-eslint 8.71.1 (MIT)
  Sources: GitHub releases; https://registry.npmjs.org/
- **Image**: none official. Build one with a pinned `node_modules` (eslint, plugin,
  formatter, `@typescript-eslint/parser`) baked in.
- **License**: ESLint MIT; plugin Apache-2.0.
- **Offline invocation** (flat config only in ESLint 10):
  ```sh
  cd /opt/eslint && npx --offline eslint --no-config-lookup -c /opt/eslint/eslint.config.mjs \
    --no-inline-config --no-warn-ignored --no-error-on-unmatched-pattern \
    -f @microsoft/eslint-formatter-sarif -o /work/out/eslint.sarif \
    --ignore-pattern '**/node_modules/**' --ignore-pattern '**/dist/**' '/work/src/**/*.{js,cjs,mjs,jsx,ts,tsx}'
  ```
  - `-c` uses the given config instead of looking up `eslint.config.*`.
  - `--no-config-lookup` disables config lookup.
  - `--no-inline-config` ignores `eslint-disable` comments in the repo.
  - Exit codes: 0 ok; 1 lint errors (or too many warnings with `--max-warnings`);
    2 config or internal error.
  Source: https://eslint.org/docs/latest/use/command-line-interface
- **Security note**: ESLint config files are JavaScript and run when loaded. Never load
  repo configs.
- **Network**: none once dependencies are baked into the image.
- **Value**: the plugin is noisy. The README says it "finds a lot of false positives
  which need triage by a human". Rules include detect-child-process,
  detect-eval-with-expression, detect-non-literal-fs-filename, detect-object-injection,
  and others.
  Source: https://github.com/eslint-community/eslint-plugin-security
- **Parsing**: SARIF `ruleId` = `security/detect-...`. Level comes from the rule severity
  (warn maps to warning). No CWE: map it yourself.

## Brakeman

- **Version**: 8.1.0 (2026-09-30), gem 8.1.0. Sources:
  https://github.com/presidentbeef/brakeman/releases , https://rubygems.org/gems/brakeman
- **Image**: `presidentbeef/brakeman` (Docker Hub).
- **License**: **Brakeman Public Use License (Synopsys)**. Not OSI. Commercial use,
  explicitly including "commercial managed/Software-as-a-Service services", requires a
  paid license. **License red flag.**
  Source: https://github.com/presidentbeef/brakeman/blob/main/LICENSE.md
- **Offline invocation**:
  ```sh
  brakeman -q --no-pager --no-progress -p /work/src -f sarif -o /work/out/brakeman.sarif \
    --no-exit-on-warn --no-exit-on-error --skip-files vendor/ --force-scan
  ```
  - `-f` accepts text, html, csv, tabs, json, markdown, codeclimate, plain, table,
    junit, sarif, sonar, github.
  - Several `-o` flags are allowed.
  - `--ensure-latest` is the only version-check feature, and it is opt-in.
  - The app's `config/brakeman.yml` is read by default.
  - `--allow-check-paths-in-config` is needed for config to load check code, so leave
    it off.
  Source: https://github.com/presidentbeef/brakeman/blob/main/lib/brakeman/options.rb
- **Network**: none.
- **Parsing**: JSON `warnings[].{warning_type, warning_code, check_name, fingerprint, message, file, line, confidence (High/Medium/Weak), cwe_id[]}`.
  Brakeman has no severity, only confidence. (`cwe_id`: **UNVERIFIED** for 8.x.)

## SpotBugs + FindSecBugs

- **Versions**: SpotBugs 4.10.4 (2026-08-20); FindSecBugs 1.14.0 (2025-06-17).
  Sources: https://github.com/spotbugs/spotbugs/releases ,
  https://github.com/find-sec-bugs/find-sec-bugs/releases
- **Image**: none official (**UNVERIFIED**). Build one with a JRE plus both jars.
- **License**: SpotBugs LGPL-2.1; FindSecBugs LGPL-3.0.
- **Blocker**: SpotBugs analyses **compiled bytecode** (jar/class). The FindSecBugs CLI
  accepts "jar/zip/class files, directories". Under scanX's no-build rule it only works
  when the repo already contains jars/classes, or when the user uploads build artifacts.
  Source: https://github.com/find-sec-bugs/find-sec-bugs/wiki/CLI-Tutorial
- **Offline invocation**:
  ```sh
  java -jar /opt/spotbugs/lib/spotbugs.jar -textui -quiet -effort:max -low \
    -pluginList /opt/findsecbugs-plugin-1.14.0.jar -include /opt/fsb-include.xml \
    -sarif=/work/out/spotbugs.sarif -auxclasspath /work/src/lib /work/src/target/classes
  ```
  `-exitcode` sets a bitmask: 1 = bugs found, 2 = missing classes, 4 = errors.
  Sources: https://spotbugs.readthedocs.io/en/latest/running.html ,
  https://github.com/spotbugs/spotbugs/blob/master/spotbugs/src/main/java/edu/umd/cs/findbugs/ExitCodes.java
- **Network**: none.
- **Parsing**: SARIF includes a CWE `taxonomies` run component (WeaknessCatalog). Rule id
  is the bug pattern, e.g. `SQL_INJECTION_JDBC`. Rank/priority maps to level.
  Source: SarifBugReporter.java in the spotbugs repo.

## Security Code Scan (.NET)

- **Version**: 5.6.7 (2022-09-05). Last push to the repo was 2024-07. **Effectively
  unmaintained.** Source: https://github.com/security-code-scan/security-code-scan
- **License**: LGPL-3.0.
- **Invocation**: `dotnet tool install --global security-scan` then
  `security-scan /src/solution.sln` (a SARIF option exists; exact flag **UNVERIFIED**).
  Source: https://security-code-scan.github.io/
- **Blocker**: it is a Roslyn analyzer. The standalone runner opens the solution through
  MSBuild, which evaluates the project files (MSBuild tasks and targets can run code) and
  needs restored NuGet references (network).
- **Recommendation**: do not include it. Cover C# with Opengrep C# rules (GitLab
  sast-rules has a `csharp` set) and DevSkim.

## Gitleaks

- **Version**: v8.30.1 (2026-03-21). Source: https://github.com/gitleaks/gitleaks/releases
- **Image**: `zricethezav/gitleaks`, `ghcr.io/gitleaks/gitleaks`.
- **License**: MIT. Default rules are embedded (MIT).
- **Maintenance note**: the original author (Zach Rice) started **Betterleaks** in 2026
  after losing full control of Gitleaks. Gitleaks has had no release since 2026-03.
  See the Betterleaks section.
  Source: https://bleepingcomputer.com/news/security/betterleaks-a-new-open-source-secrets-scanner-to-replace-gitleaks
- **Offline invocation (dir mode)**:
  ```sh
  gitleaks dir /work/src -c /opt/gitleaks.toml -i /opt/empty \
    -f sarif -r /work/out/gitleaks.sarif --redact --no-banner --exit-code 0 \
    --max-target-megabytes 10
  ```
- **Git history mode**:
  ```sh
  git config --global --add safe.directory '*'   # source is owned by another uid and mounted read-only
  gitleaks git /work/src -c /opt/gitleaks.toml -f json -r /work/out/gitleaks.json --redact \
    --exit-code 0 --log-opts="--all"
  ```
  This needs the `git` binary in the image and a `.git` directory in the mount.
  (The safe.directory step is a scanX suggestion, **UNVERIFIED** in gitleaks docs.)
- **Config precedence**: `--config`, then `GITLEAKS_CONFIG`, then `GITLEAKS_CONFIG_TOML`,
  then `(target)/.gitleaks.toml`. A repo could ship a `.gitleaks.toml` that disables
  rules, so always pass `-c`.
  - `.gitleaksignore` is read from `-i` (default "."). Point it at a scanX-controlled path.
  - Default exit code on leaks is 1; `--exit-code` overrides it.
  Source: https://github.com/gitleaks/gitleaks#readme
- **Network**: none.
- **Parsing**: JSON `[{RuleID, Description, File, StartLine, EndLine, StartColumn, Secret, Match, Entropy, Fingerprint, Commit, Author, Email, Date, Tags}]`.
  - No severity: assign one per RuleID.
  - Always use `--redact` so plaintext secrets are not stored.
  (Field list: **UNVERIFIED** against v8.30.1. Sample reports are linked in the README.)

## TruffleHog (filesystem, no verification)

- **Version**: v3.98.1 (2026-10-06). Source: https://github.com/trufflesecurity/trufflehog/releases
- **Image**: `trufflesecurity/trufflehog`, `ghcr.io/trufflesecurity/trufflehog`.
- **License**: **AGPL-3.0**.
- **Offline invocation**:
  ```sh
  trufflehog filesystem /work/src --no-verification --no-update --json \
    --results=unverified,unknown --exclude-paths=/opt/th-exclude.txt --log-level=-1 \
    > /work/out/trufflehog.jsonl
  ```
  - `--sarif` is also available. It is buffered in memory until the end of the scan.
  - `--fail` makes the run exit 183 when results are found.
  - `--no-update` disables the update check.
  - `-x/--exclude-paths` and `-i/--include-paths` take a file of newline-separated regexes.
  - Verification makes HTTP calls to provider APIs. `--no-verification` is mandatory
    under `--network none`, and it also avoids sending secrets to third parties.
  Sources: https://github.com/trufflesecurity/trufflehog#readme ,
  https://github.com/trufflesecurity/trufflehog/blob/main/main.go
- **Parsing**: JSON lines. Each line is
  `{SourceMetadata.Data.Filesystem.{file,line}, DetectorName, DetectorType, Verified, Raw, Redacted, ExtraData}`.
  - No severity.
  - **Do not persist `Raw`.** It contains the secret.
  (Field names: **UNVERIFIED** against v3.98.1.)

## Trivy (fs: vuln / license / misconfig / secret)

- **Version**: v0.75.0 (2026-10-01). Source: https://github.com/aquasecurity/trivy/releases
- **Image**: `aquasec/trivy` (Docker Hub), `ghcr.io/aquasecurity/trivy`.
  - **Pin by digest. Never use v0.69.4, v0.69.5 or v0.69.6.** See cross-cutting
    finding 2 for the 2026 incidents.
- **License**: Apache-2.0. trivy-db code is Apache-2.0. trivy-checks (misconfig) is MIT.
  DB contents come from many feeds (see licenses.md).
- **Offline invocation**:
  ```sh
  trivy fs /work/src --scanners vuln,misconfig,secret,license \
    --cache-dir /opt/trivy-cache --skip-db-update --skip-java-db-update --skip-check-update \
    --offline-scan --skip-version-check --disable-telemetry \
    --format sarif --output /work/out/trivy.sarif --exit-code 0 \
    --skip-dirs node_modules --skip-dirs vendor
  ```
  - Run a second time with `--format json` if richer data is needed. The JSON has license
    category, fixed version, and so on.
  - Pre-download the DBs at image build time:
    `trivy image --download-db-only --cache-dir /opt/trivy-cache` and
    `trivy image --download-java-db-only --cache-dir /opt/trivy-cache`.
  - The checks bundle is **embedded in the binary** and used as a fallback. No separate
    download command exists.
  - Cache paths: `db/trivy.db`, `java-db/trivy-java.db`, `policy/content`.
  - DB registries, in default order: `mirror.gcr.io/aquasec`, then `ghcr.io/aquasecurity`.
    `--db-repository` overrides this for a self-hosted mirror.
  - Use `--skip-version-check` plus `--disable-telemetry`. Both are needed to stop all
    calls to `check.trivy.dev`.
  - `--offline-scan` stops Maven Central lookups.
  - Remote Terraform modules and VEX Hub would also need network.
  Sources: https://github.com/aquasecurity/trivy/blob/main/docs/guide/advanced/air-gap.md ,
  https://github.com/aquasecurity/trivy/blob/main/docs/guide/configuration/db.md
- **DB freshness**: the DB is rebuilt every few hours upstream. scanX needs a DB-updater
  job (a separate container *with* network) that refreshes `/opt/trivy-cache` read-only
  volumes.
- **Parsing**: JSON `Results[]` (one per target file) with:
  - `Vulnerabilities[].{VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, CweIDs, CVSS, PrimaryURL}`
  - `Misconfigurations[].{ID, AVDID, Severity, Title, CauseMetadata.StartLine/EndLine}`
  - `Secrets[].{RuleID, Severity, StartLine, Match}` (Match is redacted)
  - `Licenses[].{Name, Category, Severity, FilePath, Confidence}`

  In SARIF, the rule id is the CVE/AVD/secret rule id, and `rules[].properties` has
  `security-severity` and tags. Vulnerability results point at the lockfile, often at
  line 1. (Field names: **UNVERIFIED** against v0.75.0.)

## OSV-Scanner

- **Version**: v2.6.0 (2026-09-14). Source: https://github.com/google/osv-scanner/releases
- **Image**: `ghcr.io/google/osv-scanner`. Source: https://github.com/orgs/google/packages
- **License**: Apache-2.0. Data comes from OSV.dev, with per-source licenses (see
  licenses.md).
- **Offline invocation**:
  ```sh
  OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db \
  osv-scanner scan source -r --offline --format sarif --output-file /work/out/osv.sarif /work/src
  ```
  - Pre-download per ecosystem from
    `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip` into
    `/opt/osv-db/osv-scanner/<ECOSYSTEM>/all.zip`. The ecosystem list is at
    `.../ecosystems.txt`.
  - Alternative: run `--offline-vulnerabilities --download-offline-databases` in the
    updater container.
  - `--offline` sends nothing and downloads nothing. It errors if the DB is missing.
  - Transitive dependency resolution (e.g. Maven `pom.xml` without a lockfile) needs
    network. Use `--offline` to disable it.
  - Exit codes: 0 no vulnerabilities; 1 vulnerabilities found; 127 general error;
    128 no packages found.
  Sources: https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md ,
  https://github.com/google/osv-scanner/blob/main/docs/usage.md ,
  https://github.com/google/osv-scanner/blob/main/docs/output.md
- **Licenses**: `--licenses` uses the deps.dev API, so it is **not available offline**.
  Use Trivy or ScanCode for licenses.
  Source: https://github.com/google/osv-scanner/blob/main/docs/license-scanning.md
- **Parsing**: in SARIF, each vulnerability (grouped by aliases) is a rule and each
  affected package is a result. JSON:
  `results[].packages[].{package{name,version,ecosystem}, vulnerabilities[], groups[{ids, max_severity}]}`.
  `max_severity` is a CVSS score string.

## Grype

- **Version**: v0.120.0 (2026-10-02). Source: https://github.com/anchore/grype/releases
- **Image**: `anchore/grype`, `ghcr.io/anchore/grype`.
- **License**: Apache-2.0 (engine and grype-db builder). See licenses.md for DB contents.
- **Offline invocation**:
  ```sh
  GRYPE_DB_CACHE_DIR=/opt/grype-db GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=false \
  GRYPE_CHECK_FOR_APP_UPDATE=false \
  grype dir:/work/src -o sarif --file /work/out/grype.sarif --exclude './node_modules/**'
  ```
  - Better: run `grype sbom:/work/out/syft.cdx.json`, reusing the Syft SBOM.
  - `--fail-on <severity>` sets a non-zero exit.
  - Config keys: `db.cache-dir`, `db.auto-update`, `db.validate-age`,
    `db.max-allowed-built-age` (default 5 days), `db.require-update-check`,
    `db.update-url` (default `https://grype.anchore.io/databases`),
    `check-for-app-update`.
  - Env vars follow the `GRYPE_` + upper-snake convention (the exact names above are
    **UNVERIFIED** but follow the clio convention).
  - Pre-download with `grype db download` in the updater, or `grype db import <archive>`.
  Sources: https://github.com/anchore/grype/blob/main/cmd/grype/cli/options/database.go ,
  https://github.com/anchore/grype/blob/main/grype/db/v6/distribution/client.go ,
  https://developer.harness.io/docs/security-testing-orchestration/sto-techref-category/grype/grype-setup-in-airgapped
- **Parsing**: JSON `matches[].{vulnerability{id, severity, cvss, fix{versions,state}}, artifact{name, version, type, purl, locations[].path}, matchDetails}`.
  CWE is not provided directly (**UNVERIFIED**).

## Syft (CycloneDX SBOM)

- **Version**: v1.54.0 (2026-10-01). Source: https://github.com/anchore/syft/releases
- **Image**: `anchore/syft`, `ghcr.io/anchore/syft`.
- **License**: Apache-2.0.
- **Offline invocation**:
  ```sh
  SYFT_CHECK_FOR_APP_UPDATE=false syft dir:/work/src \
    -o cyclonedx-json=/work/out/sbom.cdx.json -o syft-json=/work/out/sbom.syft.json \
    --exclude './node_modules/**'
  ```
  Source (output syntax): https://github.com/anchore/syft#readme
- **Network**: all remote enrichment defaults to **false** in source:
  - `java.use-network`
  - `golang.search-remote-licenses`
  - `javascript.search-remote-licenses`
  - `python.search-remote-licenses`
  - Maven repository use

  Keep them off.
  Source: https://github.com/anchore/syft/blob/main/cmd/syft/internal/options/catalog.go
- **Parsing**: standard CycloneDX 1.6 JSON, `components[].{name, version, purl, licenses}`
  (spec version **UNVERIFIED**).

## govulncheck

- **Version**: golang.org/x/vuln v1.8.0 (2026-09-08), from proxy.golang.org. The GitHub
  mirror "latest release" (v1.1.4) is stale.
  Source: https://proxy.golang.org/golang.org/x/vuln/@latest
- **Image**: none official. Build one with a Go toolchain.
- **License**: BSD-3-Clause. Go vuln DB entries are CC-BY-4.0.
  Source: https://github.com/golang/vulndb#license
- **Offline invocation**:
  ```sh
  cd /work/src && GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local \
  govulncheck -db file:///opt/govulndb -format sarif ./... > /work/out/govulncheck.sarif
  ```
  - `-db` accepts http://, https:// and file://.
  - Offline DB: unzip `https://vuln.go.dev/vulndb.zip` into `/opt/govulndb`.
  - `-scan module|package|symbol` (default symbol).
  - `-mode source|binary|extract`.
  - With `-format json|sarif|openvex`, exit is 0 even when vulnerabilities are found.
  Sources: https://github.com/golang/vuln/blob/master/cmd/govulncheck/doc.go ,
  https://github.com/golang/vuln/blob/master/internal/scan/flags.go ,
  https://go.dev/security/vuln/database
- **Limitation**: source mode (symbol or package level) loads packages with full
  dependencies, so the module cache must be populated (network) unless `vendor/` exists.
  - `-scan module` only needs `go.mod`. It gives module-level results, equivalent to
    OSV/Trivy.
  - Without network, use `-scan module`, or rely on OSV-Scanner/Trivy for Go.
  - (Behaviour of `-scan module` without a module cache: **UNVERIFIED**.)
- **Parsing**: SARIF results per OSV id (GO-YYYY-NNNN). JSON is a stream of
  `{config|progress|osv|finding}` messages.

## Checkov

- **Version**: 3.3.23 (2026-10-05). Source: https://github.com/bridgecrewio/checkov/releases
- **Image**: `bridgecrew/checkov`, `ghcr.io/bridgecrewio/checkov`.
- **License**: Apache-2.0. Built-in policies are in the same repo (Apache-2.0).
- **Offline invocation**:
  ```sh
  cd /tmp && checkov -d /work/src --skip-download --download-external-modules false \
    --skip-framework sca_package --skip-framework sca_image \
    -o sarif -o json --output-file-path /work/out/checkov.sarif,/work/out/checkov.json \
    --soft-fail --quiet --compact --skip-path node_modules --config-file /opt/checkov.yaml
  ```
  - `--skip-download` stops downloading data from Prisma Cloud. **This also omits
    severities and doc links.**
  - `--download-external-modules` controls Terraform module download.
  - `-s/--soft-fail` forces exit 0. `--hard-fail-on` and `--soft-fail-on` are also
    available.
  - `-o` formats: cli, csv, cyclonedx, cyclonedx_json, spdx, json, junitxml,
    github_failed_only, gitlab_sast, sarif.
  - `IGNORED_DIRECTORIES` env var (default `node_modules,.terraform,.serverless`).
  Source: https://github.com/bridgecrewio/checkov/blob/main/docs/2.Basics/CLI%20Command%20Reference.md
- **Security note**: never pass `--external-checks-dir` or `--external-checks-git` from
  repo config (they load Python checks). Run with the working directory outside the repo
  and pass an explicit `--config-file`. `sca_*` frameworks need a Prisma API key.
- **Parsing**: JSON `results.failed_checks[].{check_id (CKV_*), check_name, file_path, file_line_range, resource, severity, guideline}`.
  **`severity` is null in OSS mode without a platform key.** scanX needs its own
  severity map per CKV id.

## KICS

- **Version**: v2.2.0 (2026-09-17) on GitHub. **Docker Hub `checkmarx/kics` is still at
  v2.1.20 (last update 2026-04-22, the day of the malicious-image incident).**
  Sources: https://github.com/Checkmarx/kics/releases , https://hub.docker.com/r/checkmarx/kics ,
  https://thehackernews.com/2026/04/malicious-kics-docker-images-and-vs.html
- **License**: Apache-2.0. Queries (Rego) are in the same repo.
- **Offline invocation**:
  ```sh
  kics scan -p /work/src -o /work/out --output-name kics --report-formats sarif,json \
    --no-progress --ci --ignore-on-exit results --exclude-paths '/work/src/node_modules/*' \
    -q /opt/kics/assets/queries -b /opt/kics/assets/libraries
  ```
  - Default queries path is `./assets/queries`, so ship assets in the image.
  - `--fail-on` defaults to all severities.
  - `--disable-secrets` turns off the secrets engine.
  - Results exit codes: 60 critical, 50 high, 40 medium, 30 low, 20 info. Errors: 70
    remediation, 126 engine, 130 SIGINT.
  - v2 flag files no longer contain `--disable-full-descriptions` or telemetry flags.
  Sources: https://github.com/Checkmarx/kics/blob/master/docs/commands.md ,
  https://github.com/Checkmarx/kics/blob/master/internal/console/flags/scan_flags.go ,
  https://github.com/Checkmarx/kics/blob/master/docs/results.md
- **Network**: none for local scans (**UNVERIFIED** for v2.2.0 at runtime; confirm with
  `--network none`).
- **Parsing**: JSON `queries[].{query_id (UUID), query_name, severity, platform, cwe, files[].{file_name, line, issue_type, expected_value, actual_value, similarity_id}}`.
  (`cwe` field presence: **UNVERIFIED**.)

## Hadolint

- **Version**: v2.15.1 (2026-07-31). Source: https://github.com/hadolint/hadolint/releases
- **Image**: `hadolint/hadolint`, `ghcr.io/hadolint/hadolint`.
- **License**: GPL-3.0. It embeds ShellCheck (GPL-3.0) for `RUN` checks.
- **Offline invocation** (takes file arguments, so scanX must find the Dockerfiles first):
  ```sh
  hadolint --no-fail --no-color -c /opt/hadolint.yaml -f sarif $(find /work/src -name 'Dockerfile*' -o -name '*.Dockerfile') \
    > /work/out/hadolint.sarif
  ```
  - Formats: tty, json, checkstyle, codeclimate, gitlab_codeclimate, gnu, codacy,
    sonarqube, sarif, junit.
  - `-t/--failure-threshold` sets the failing level.
  - `--disable-ignore-pragma` ignores inline ignores.
  Source: https://github.com/hadolint/hadolint#readme
- **Network**: none.
- **Parsing**: rule ids DL3xxx/DL4xxx (Hadolint) and SCxxxx (ShellCheck). Level is
  error/warning/info/style. No CWE.

## ShellCheck

- **Version**: v0.11.0 (2025-08-04). Source: https://github.com/koalaman/shellcheck/releases
- **Image**: `koalaman/shellcheck`, `koalaman/shellcheck-alpine` (Docker Hub).
- **License**: GPL-3.0.
- **Offline invocation** (scanX must find shell scripts first):
  ```sh
  shellcheck --norc -f json1 -S warning $(files) > /work/out/shellcheck.json
  ```
  - **No SARIF.** Formats: checkstyle, diff, gcc, json, json1, quiet, tty.
  - `--norc` ignores the repo's `.shellcheckrc`.
  - `--files-from FILE` reads the file list.
  - Exit codes: 0 ok, 1 issues found, other values are errors (see the man page
    "RETURN VALUES").
  Source: https://github.com/koalaman/shellcheck/blob/master/shellcheck.1.md
- **Network**: none.
- **Parsing**: json1 `comments[].{file, line, endLine, column, level, code, message, fix}`.
  The code is numeric (SC2086 is 2086). No CWE.

## OWASP ZAP baseline

- **Version**: ZAP 2.17.0 (2025-12-15). Source: https://github.com/zaproxy/zaproxy/releases
- **Image**: `ghcr.io/zaproxy/zaproxy:stable` (recommended), `zaproxy/zap-stable`.
- **License**: Apache-2.0.
- **Invocation**:
  ```sh
  zap-baseline.py -t https://target -J zap.json -r zap.html -I
  ```
  - `-I` means "do not return failure on warning".
  - Exit codes: 0 ok, 1 FAIL, 2 WARN, 3 other error.
  Source: https://www.zaproxy.org/docs/docker/baseline-scan/
- **Not compatible with the scanX source model.** It is DAST: it needs a running target
  reachable over the network and cannot scan a source directory. Treat it as an
  optional, separate "DAST job" with its own network policy and explicit target
  authorisation. It also checks for add-on updates at startup unless configured
  otherwise (**UNVERIFIED**).

## sonar-scanner

- **Version**: sonar-scanner-cli 8.1.0.6389 (2026-04-21). SonarQube server 26.9.0.
  Sources: https://github.com/SonarSource/sonar-scanner-cli/releases ,
  https://github.com/SonarSource/sonarqube/releases
- **Image**: `sonarsource/sonar-scanner-cli`.
- **License**: scanner CLI LGPL-3.0; SonarQube platform LGPL-3.0. **The language
  analyzers (sonar-java, sonar-php, sonar-python, SonarJS, sonar-dotnet) are under the
  SONAR Source-Available License v1.0 (2024-11-13).** That license forbids "Competing"
  use (offering substantially similar functionality to SonarQube) and AI ingestion of
  output.
  Sources: https://github.com/SonarSource/sonar-java/blob/master/LICENSE.txt , and the
  equivalents in the other analyzer repos.
- **Not compatible**: the scanner uploads to a SonarQube server, which runs the analysis.
  It needs network and a server, and Java analysis needs compiled classes. The analyzer
  license is a SaaS red flag for scanX. **Exclude, or support only as a "bring your own
  SonarQube" integration that the user runs.**

---

## Other actively maintained OSS scanners worth adding

| Tool | Area | Version (date) | License | Offline? | Notes / invocation | Source |
|---|---|---|---|---|---|---|
| **Betterleaks** | Secrets | v1.9.0 (2026-09-29); v2 in RC | MIT | Yes. Validation is opt-in (`-v`) and off by default. | Successor to Gitleaks by the same author. `betterleaks fs /work/src`, `betterleaks git /path`. Image `ghcr.io/betterleaks/betterleaks:v1` / `:v2`. Report flags **UNVERIFIED**. | https://github.com/betterleaks/betterleaks |
| detect-secrets | Secrets | v1.5.0 (2024-05-06) | Apache-2.0 | Yes | Slow release cadence | https://github.com/Yelp/detect-secrets |
| 2ms (Checkmarx) | Secrets | v5.4.0 (2026-09-16) | Apache-2.0 | Yes (**UNVERIFIED**) | | https://github.com/Checkmarx/2ms |
| **zizmor** | GitHub Actions | v1.30.1 (2026-09-09) | MIT | Yes. Offline unless a GH token is set; `--offline` forces it. | `zizmor --offline --format sarif /work/src` | https://docs.zizmor.sh/usage/ |
| actionlint | GitHub Actions | v1.7.12 (2026-03-30) | MIT | Yes | Embeds ShellCheck if present | https://github.com/rhysd/actionlint |
| **cppcheck** | C/C++ | 2.22.0 (2026-09-19) | GPL-3.0 | Yes | `--output-format=sarif` (accepts text/sarif/xml/xmlv2/xmlv3). Repo moved to `cppcheck-opensource/cppcheck`. | https://github.com/cppcheck-opensource/cppcheck |
| flawfinder | C/C++ | 2.0.20 per source (release date **UNVERIFIED**) | GPL-2.0 | Yes | `--sarif`. CWE taxonomy in output. | https://github.com/david-a-wheeler/flawfinder |
| cargo-audit | Rust deps | 0.22.2 (crates.io) | Apache-2.0 OR MIT; RustSec DB CC0-1.0 | Yes, with a pre-cloned advisory-db (`--db <path> --no-fetch`; flags **UNVERIFIED**) | | https://crates.io/crates/cargo-audit , https://github.com/rustsec/advisory-db |
| cargo-deny | Rust deps/licenses | 0.20.2 (2026-07-09) | MIT / Apache-2.0 | Yes, with a pre-fetched DB (**UNVERIFIED**) | | https://github.com/EmbarkStudios/cargo-deny |
| bundler-audit | Ruby deps | v0.9.3 (2025-11-28) | GPL-3.0; ruby-advisory-db is public domain | Yes (`--no-update` with a local DB) | OSV/Trivy already cover RubyGems | https://github.com/rubysec/bundler-audit |
| PMD | Java/Apex/etc. | 7.28.0 (2026-09-25) | BSD-style | Yes, source-level (no build) | `pmd check -d /work/src -R <ruleset> -f sarif`. Has a few security rules; mostly quality. | https://github.com/pmd/pmd |
| detekt | Kotlin | v1.23.8 (2025-02-21) | Apache-2.0 | Yes | Mostly quality, few security rules. SARIF supported. | https://github.com/detekt/detekt |
| mobsfscan | Android/iOS source (Java/Kotlin/Swift/ObjC) | 1.0.1 (2026-09-21) | LGPL-3.0 | Yes | Same family as njsscan; SARIF supported | https://github.com/MobSF/mobsfscan |
| DevSkim | Multi-language patterns | v1.0.100 (2026-09-29) | MIT | Yes | SARIF native | https://github.com/microsoft/DevSkim |
| kube-linter | Kubernetes YAML/Helm | v0.8.3 (2026-03-10) | Apache-2.0 | Yes | `stackrox/kube-linter` image | https://github.com/stackrox/kube-linter |
| kubescape | Kubernetes / IaC | v4.0.15 (2026-09-29) | Apache-2.0 | Yes, after `kubescape download artifacts`, then `--use-artifacts-from` | `--format sarif` (local files only). Telemetry defaults **UNVERIFIED**. | https://github.com/kubescape/kubescape/blob/master/docs/getting-started.md |
| tflint | Terraform | v0.64.0 (2026-07-17) | MPL-2.0 | Yes, with bundled plugins only (plugins download from GitHub otherwise) | Lint, some security | https://github.com/terraform-linters/tflint |
| ScanCode Toolkit | License/copyright detection | v32.5.0 (2026-01-15) | Apache-2.0 code; CC-BY-4.0 data | Yes | The reference license scanner. Slow but thorough. | https://github.com/aboutcode-org/scancode-toolkit |
| osv-scalibr | Inventory/SCA library (powers OSV-Scanner) | v0.5.3 (2026-09-22) | Apache-2.0 | Yes | | https://github.com/google/osv-scalibr |
| retire.js | Vulnerable JS libs (including vendored/minified) | 6.1.0 (2026-10-06) | Apache-2.0 | Yes, with a local repo file (flag **UNVERIFIED**) | Catches copied-in jQuery etc. that lockfile scanners miss. Data license **UNVERIFIED**. | https://github.com/RetireJS/retire.js |
| OWASP dep-scan | SCA + reachability | v6.3.0 (2026-07-23) | MIT | Partly (**UNVERIFIED**) | Uses cdxgen (Apache-2.0) | https://github.com/owasp-dep-scan/dep-scan |
| OWASP Dependency-Check | Java/.NET SCA | v12.1.0 (2025-02-17) | Apache-2.0 | Yes, with a pre-built data dir. NVD API key needed to update. | Heavy; NVD terms notice applies | https://github.com/jeremylong/DependencyCheck |
| nuclei | DAST templates | v3.11.1 (2026-08-08) | MIT | No (DAST) | Optional DAST job only | https://github.com/projectdiscovery/nuclei |

**Not recommended**:

| Tool | Reason | Source |
|---|---|---|
| Bearer | Elastic License 2.0, which bans providing it as a managed service | https://github.com/Bearer/bearer/blob/main/LICENSE.txt |
| CodeQL | GitHub CodeQL Terms and Conditions; not OSI | https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md |
| SonarQube analyzers | SSAL v1.0 | see the sonar-scanner section |
| Safety | DB under CC-BY-NC-4.0 | https://github.com/pyupio/safety-db |
| Terrascan | Archived (last release v1.19.9, 2024-09) | https://github.com/tenable/terrascan |
| tfsec | Superseded by Trivy | https://github.com/aquasecurity/tfsec |
| Horusec | Last release 2022 | https://github.com/ZupIT/horusec |
| Security Code Scan | Unmaintained; needs MSBuild | see its section |
| Infer (MIT) | Requires compiling the code | https://github.com/facebook/infer |
| MegaLinter | AGPL-3.0 aggregator; better to integrate the tools directly | https://github.com/oxsecurity/megalinter |

Swift and Dart have no strong dedicated OSS security SAST:

- **Swift**: use mobsfscan plus Opengrep Swift rules. SwiftLint (MIT, 0.65.1) is a style
  linter. Source: https://github.com/realm/SwiftLint
- **Dart**: OSV-Scanner and Trivy cover pub dependencies.
