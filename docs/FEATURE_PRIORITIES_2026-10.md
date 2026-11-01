# Feature priorities

Ranked against default-branch source, open work and recent CI on November 1, 2026.
Effort and risk are relative estimates; this document records priorities, not a release schedule.

| Status / rank | Candidate | Value | Effort | Risk | Reason |
| --- | --- | --- | --- | --- | --- |
| Complete | Explicit sanitized diagnostic export | High | Small | Low | Available on `main`; the explicit JSON download includes finding titles and claim names, omitting raw tokens and decoded values. |
| 1 | Authenticated Graph execution with tenant/account context and impact preview | High | Large | High | Lets analysts run documented requests with explicit authority. Require user initiation, least privilege, and a method/target/body/impact preview before mutations. Keep local checks distinct from authenticated results; development checks must not change a live tenant. |
| 2 | Sanitized case workspace with field-level review | High | Medium | Medium | Lets analysts assemble safe artifacts and explicitly review each field before saving or exporting. |
