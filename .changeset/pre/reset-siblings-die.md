---
"@strutvane/auth": patch
---

The Better Auth adapter now invalidates every other outstanding password-reset token of a user when a reset completes, matching the native engine. Previously an older reset link stayed usable after the password had been reset. The identity contract suite (`@strutvane/auth/testing`) checks this for every engine.
