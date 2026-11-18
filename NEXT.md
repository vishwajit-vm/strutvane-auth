# NEXT: `v2/native-engine` (@strutvane/auth 0.2 core train)

Branch progress for the next session (HANDOFF §2 rule 5). Status of the whole ecosystem is in the hub's `STATE.md`.

## Done (2026-11-18)

- **Framework 0.2 error model.** Peer and dev dependency on `@strutvane/framework` `^0.2.0-next.0` / `0.2.0-next.0`, and `strutvane.compat` `^0.2.0-next.0` (CONSISTENCY #128; `test/packaging.test.ts`).
- **Lowercase codes (#68, #123).** Every code auth throws, compares, registers or reports is lowercase `snake_case`: provider and middleware problems (`forbidden`, `not_found`, `validation_failed`, `tenant_required`, `malformed_request`, `unsupported_media_type`, `payload_too_large`), `invalid_filter`, `AUTH_ERRORS` (now also `two_factor_required`, `email_not_verified` and `malformed_request`, so they render with titles), and the `tenancyAudit` / `findSessionSet` / `relationKeyAudit` finding codes.
- **`test/error-codes-source.test.ts`** fails on any uppercase code in `src`, in every shape. Its allow-list is exact: Node module and warning codes, plus SQLSTATE values. It also checks that every client-facing code is registered and that an auth issue is a framework `ValidationIssue` (#69, `field`).
- The release patch `release/0.2/patches/auth/0001-…` was already applied (81dcbb0).
- Changeset: `.changeset/lowercase-error-codes.md` (minor, core train).

## Not done / waiting

- **The lockfile must be refreshed after the framework is published.** `@strutvane/framework` 0.2.0-next.0 is not on npm yet. Its lockfile entry has the registry URL and no integrity hash: it was generated from a tarball packed from framework `main` 6dfc239, then pointed back at the registry. `npm ci` cannot fetch it until the framework is published. After publishing, run `npm install` (it fills in the integrity), then `npm run ci`, and commit `package-lock.json`.
- **Not pushed** (the coordinator pushes).
- R2 matrix (Linux/macOS, Node 26), R3 `security-reviewer` pass, R4 soak, R6–R8: unchanged; see `RELEASE-READINESS.md`.

## How to verify locally (before the framework is on npm)

```bash
# in a framework checkout at main (6dfc239 or later)
npm ci && npm run build && npm pack --pack-destination <dir>
# in this repo
npm install --no-save --no-audit --no-fund <dir>/strutvane-framework-0.2.0-next.0.tgz
npm run ci                      # 3x in a row
npm run test:integration        # needs Docker; starts and removes its own postgres:18.7-alpine container
```

`--no-save` keeps `package.json` and `package-lock.json` untouched. Never commit a `file:` spec or a lockfile entry that points at the tarball, because CI (`check-deps.mjs`) refuses them.
