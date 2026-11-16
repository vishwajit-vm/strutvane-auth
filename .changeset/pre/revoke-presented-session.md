---
"@strutvane/auth": patch
---

The Better Auth engine revokes the session the browser presented when a sign-in issues a new one (defence in depth against session fixation), as the native engine already did; the identity contract now checks it for every engine.
