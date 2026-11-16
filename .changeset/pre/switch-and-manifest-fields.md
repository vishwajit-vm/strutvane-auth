---
"@strutvane/auth": patch
---

A refused tenant switch on the Better Auth engine no longer drops the caller's current tenant (membership is checked before Better Auth is asked). The manifest no longer offers fields an actor may not read and marks fields they may not write as read-only (`manifest.build`).
