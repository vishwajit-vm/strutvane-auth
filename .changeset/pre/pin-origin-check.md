---
"@strutvane/auth": patch
---

The Better Auth adapter now pins Better Auth's origin check for cookie-authenticated writes on. Better Auth switches that check off by itself when it detects a test environment (`NODE_ENV=test`), so a deployment running with that value lost it silently.
