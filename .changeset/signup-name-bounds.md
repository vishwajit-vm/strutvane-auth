---
"@strutvane/auth": patch
---

The Better Auth adapter now rejects sign-ups with an empty name or a name longer than 200 characters (`VALIDATION_FAILED`), like the native engine and `createUserAsSystem`. Better Auth itself accepted any name.
