---
"@strutvane/auth": patch
---

The app provider now enforces policy field rules on the resource API: fields an actor may not read are removed from every record (`resource.serialize`), and creates or updates that send a field the actor may not write are refused with 403 (`resource.beforeWrite`). Previously only filters and sorts honoured read rules.
