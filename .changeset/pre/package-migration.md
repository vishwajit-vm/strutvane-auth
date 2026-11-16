---
"@strutvane/auth": minor
---

The identity tables ship as a package migration (`migrations/postgres/`, declared through `strutvane.migrations`), so `sv migrate` creates them; `sv auth:migration` is no longer a required step.
