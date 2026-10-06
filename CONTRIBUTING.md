# Contributing to scanX

## License and CLA
scanX is source-available under the Business Source License 1.1 (see `LICENSE`); each version
converts to AGPL-3.0-or-later on its Change Date. Because İninia Teknoloji Limited Şirketi offers
commercial licenses, every contributor must sign the Contributor License Agreement before a pull
request can be merged (CLA bot on the PR — CLA text to be finalised before the first external
contribution).

## Workflow
1. Read the spec sections relevant to your change and `docs/adr/`.
2. Small, verifiable changes (≈ ≤400 lines). Tests are mandatory; bug fixes start with a failing test.
3. `scripts/dev.sh lint test test-integration` must pass.
4. Commits follow Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`, `sec:`.
5. Fill in the security checklist (spec §20.6) in the PR description.

## Rules that are not negotiable
- No secrets in the repo; fixtures use obviously FAKE values under `testdata/`.
- SQL only through sqlc-generated code; no string-built SQL.
- No `os/exec` in server/worker — external processes only via the sandbox package.
- No `templ.Raw` without an ADR.
