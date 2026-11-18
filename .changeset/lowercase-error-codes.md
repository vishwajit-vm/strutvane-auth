---
"@strutvane/auth": minor
---

**Joins the 0.2 core train on `@strutvane/framework` 0.2 (CONSISTENCY #123, #69, #128).** Breaking, pre-1.0 (a minor bump).

- The framework peer is now `^0.2.0-next.0` (was `^0.1.0-next.1 || ^0.2.0-next.0`), and `strutvane.compat` matches it.
- Every code is lowercase `snake_case`, like the framework's. Problems from the provider and middleware are `forbidden`, `not_found`, `validation_failed`, `tenant_required`, `malformed_request`, `unsupported_media_type` and `payload_too_large`. `InvalidFilterError` is `invalid_filter`. `AUTH_ERRORS` registers `invalid_filter`, `invalid_credentials`, `email_unavailable`, `invalid_token`, `two_factor_required`, `email_not_verified`, `tenant_required`, `malformed_request` and `unsupported_media_type`, so every problem auth returns renders with a proper title (`two_factor_required`, `email_not_verified` and `malformed_request` used to fall back to a humanized code).
- Finding codes are lowercase too: `tenancyAudit` (`rls_disabled`, `rls_not_forced`, `no_restrictive_policy`, `runtime_role_bypasses_rls`, `runtime_role_owns_table`, `definer_view`, `security_definer_function`, `tenant_setting_default`), `findSessionSet` (`session_set`, `session_set_config`, `set_local`, `persistent_set`, `session_reset`) and `relationKeyAudit` (`relation_table_missing`, `relation_key_not_unique`). Update CI scripts that compare the old names.
- Field issues keep `{ path, field, code, message }`, and are now checked against the framework's `ValidationIssue` type.
- A new source-scan test fails on any uppercase code in `src`.
