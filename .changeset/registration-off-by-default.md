---
"@strutvane/auth": minor
---

Public sign-up is now off by default. The app provider accepts `POST /auth/sign-up` only when `config/auth.ts` sets `registration: true`; a config that omits the key (or sets any other value) gets the existing `403 FORBIDDEN` problem. Apps that rely on open registration must set `registration: true` explicitly.
