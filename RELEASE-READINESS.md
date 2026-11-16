# Release readiness

<!--
  Created once by strutvane-tooling (canonical/RELEASE-READINESS.md). This repo owns this file:
  sync never overwrites it. Gates and rules: hub docs/19-production-readiness.md
  (https://github.com/vishwajit-vm/strutvane/blob/main/docs/19-production-readiness.md).

  A version reaches npm `latest` only when every gate below is "pass" with evidence. One row per
  gate: the status (pass / fail / not checked), a link to the evidence (CI run, report or test
  file; never "trust me"), and the date it was checked (YYYY-MM-DD). The coordinator re-runs the
  checks before a gate is accepted; the project lead approves the staged release.
-->

Package: `@strutvane/auth` · Version: `0.2.0-next.0` (branch `v2/native-engine`) · Last reviewed: 2026-11-16

| Gate | What must be true (summary; docs/19 is the source) | Checked by | Status | Evidence | Date |
|---|---|---|---|---|---|
| R1 Code | Strict TS, ESM, lint clean, no `console.` in `src/`, no TODO/FIXME without an issue, TSDoc on every export | CI `verify` (`npm run ci`, `check-code-rules.mjs`) | pass (local) | tsc strict + Biome clean; `check-code-rules.mjs`: no console in src/, no untracked TODO | 2026-11-16 |
| R2 Tests | Green on Node 24 and 26 × Linux, Windows, macOS; coverage ≥ 90/90/85/90; type-level tests; 3 green runs in a row; no unhandled rejections or open handles | CI `verify` matrix and `repeat` job | partial | Local Windows, Node 24.21: `npm run ci` green 3 runs in a row with the integration suite running concurrently (819 unit tests, coverage 94.47/90.43/93.06/95.86; integration 63). Linux/macOS and Node 26 need the CI matrix (not run: branch not pushed) | 2026-11-16 |
| R3 Security | Threat model; attack-style tests; parsers fuzzed; review with 0 open critical/high; `npm audit --omit=dev` 0 high/critical; secrets scan clean | `security-reviewer` report; CI `security` job | partial | Attack suites ported from spike 20 (two audit rounds) on 3 stores, real-PG races (`test/integration/postgres-store.test.ts`), parsers fuzzed (`test/engine/parsers.fuzz.test.ts`); `npm audit --omit=dev`: 0. Needs: `security-reviewer` pass on the port and the provider wiring, TruffleHog in CI | 2026-11-16 |
| R4 Resilience | Failure scenarios named and tested; fails closed; idempotent retries; soak test with no growth | Resilience suites; `npm run test:soak` | partial | Store failure ordering (`test/engine/storage-failures.test.ts`), database down / rollback / pool release (integration), boot fails closed (APP_KEY, tables, cookie-name mismatch). No soak test yet | 2026-11-16 |
| R5 Packaging | publint and attw clean; tarball has no tests, fixtures, secrets or local map paths; exports resolve; `engines.node` ≥ 24.3; one framework copy; LICENSE, README, CHANGELOG; a changeset | CI `package-check` job | pass (local) | `check-package.mjs` OK (94 files), publint --strict "All good", attw esm-only exit 0 (11 entry points green), engines >=24.3, framework peer `^0.1.0-next.1 \|\| ^0.2.0-next.0` (one kernel, `test/packaging.test.ts`), LICENSE/README/CHANGELOG, changeset. Lockfile framework entry has no integrity until framework 0.1.0-next.1 is published | 2026-11-16 |
| R6 Integration | Installs alone and with every package, in any order, identically; re-install is a no-op; complete `.env.example`; boot fails closed; only the six connections; Northwind Ops green | Hub nightly ecosystem job; installer e2e | not checked | Needs the hub nightly job and Northwind Ops | 2026-11-16 |
| R7 Docs | Every public feature documented with tested examples; upgrade guide; packages data, what's-new, versioning table and deprecations updated in the same change | Docs site tests | partial | README (engine, app wiring, migration guide) with a tested identity example; docs site pages and upgrade guide not updated (other repo) | 2026-11-16 |
| R8 Release | Version per ADR-0020; staged by CI with provenance, approved with 2FA (ADR-0018); right dist-tag; release notes; rollback plan; `versions.json` updated | Release workflow; owner approval | not checked | Version 0.2.0-next.0 per CONSISTENCY #128; staging needs CI and owner approval | 2026-11-16 |
| R9 Operations | Logs only through the framework Logger with redaction (ADR-0022); health and readiness checks; no debug tool reachable in production | Tests; `security:check` | pass (local) | Auth logs only through the framework Logger (no console); mails and events never carry secrets (`test/engine/redaction.test.ts`, `test/provider-v2.test.ts`) | 2026-11-16 |
