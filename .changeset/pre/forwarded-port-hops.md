---
"@strutvane/auth": patch
---

Client IP resolution behind a trusted proxy now accepts `X-Forwarded-For` hops that carry a source port (`203.0.113.7:51234`, `[2001:db8::7]:443`), as some proxies send them. Such hops used to be treated as malformed, so every client behind the proxy counted against the proxy's single per-IP rate-limit bucket and one client could block sign-in for everyone.
