---
"@strutvane/auth": patch
---

The persistent identity (`session.driver: 'database'`) now gives up on a database connection after 10 seconds. Before, a database that accepted TCP connections but never answered (black-holed or wedged) hung the app's boot and every authenticated request indefinitely; now the boot fails and requests fail closed.
