---
"@strutvane/auth": minor
---

Depend on the merged `@strutvane/framework` as a **peer** (`^0.1.0-next.1`) instead of `@strutvane/core` and `@strutvane/contracts`. Imports now use `@strutvane/framework/core` and `@strutvane/framework/contracts`, so an app has exactly one kernel: before, installing this package next to the framework added a second copy of core, and its container tokens and error classes did not match the framework's (the logger binding was not found and errors rendered as 500). Requires Node.js 24.3 or newer.
