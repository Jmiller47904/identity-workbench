# Non-human identity scanner

## Current implementation

The NHI scanner is a local analysis workspace in the browser and desktop source. It reads a normalized JSON snapshot, calculates evidence-based review signals, and displays identities, owners, workloads, permissions, credential metadata, activity, and source coverage.

It does not authenticate to provider APIs or discover tenant objects directly. Provider collectors and raw API response adapters are not implemented yet. The interface keeps input and results in page memory; it does not upload or save them. Use synthetic examples in shared material. Never include passwords, secret values, private keys, access tokens, or credential values in a snapshot.

## Import a snapshot

The scanner accepts UTF-8 JSON up to 2 MB, 1,000 source scopes, and 5,000 identity records. Per identity, it accepts up to 100 permissions, 50 credentials, 100 trust entries, and 500 activity events. Oversized arrays are rejected rather than silently truncated. Set `schemaVersion` to `1`. Stable identity IDs are unique within a provider and scope. Add source records so the scanner can describe scope and activity coverage accurately.

```json
{
  "schemaVersion": 1,
  "scannedAt": "2026-11-03T12:00:00Z",
  "sources": [
    {
      "provider": "azure",
      "scopeId": "tenant-a",
      "scopeLabel": "Production Entra tenant",
      "activityCoverage": "partial",
      "collectedAt": "2026-11-03T11:55:00Z"
    }
  ],
  "identities": [
    {
      "provider": "azure",
      "id": "service-principal-object-id",
      "displayName": "claims-sync-prod",
      "kind": "service principal",
      "scopeId": "tenant-a",
      "scopeLabel": "Production Entra tenant",
      "enabled": true,
      "owner": {
        "name": "Identity Platform",
        "email": "identity-platform@example.test",
        "team": "Identity Platform",
        "evidence": "directory owner"
      },
      "workload": "Claims reconciliation function",
      "workloadType": "Azure Function",
      "permissions": ["User.Read.All"],
      "trusts": [
        { "principal": "example workload identity", "external": false }
      ],
      "credentials": [
        {
          "id": "credential-key-id",
          "type": "certificate",
          "active": true,
          "managed": false,
          "createdAt": "2026-01-01T00:00:00Z",
          "expiresAt": "2027-01-01T00:00:00Z",
          "lastUsedAt": "2026-11-02T00:00:00Z"
        }
      ],
      "activity": [
        {
          "at": "2026-11-02T00:00:00Z",
          "action": "Token issued",
          "target": "Microsoft Graph",
          "source": "claims-sync-prod",
          "outcome": "success"
        }
      ],
      "activityCoverage": "partial",
      "providerManaged": false
    }
  ]
}
```

### Field reference

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Required integer. Version 1 is the current local format. |
| `sources` | Optional collection scope and activity coverage. Use `complete`, `partial`, or `none`; omit or use another value when coverage is unknown. Multiple scopes per provider are supported. |
| `identities[].provider` | Required lowercase value: `azure`, `aws`, `gcp`, or `okta`. |
| `identities[].id` / `displayName` | Required stable provider ID and analyst-friendly name. |
| `owner` | Optional person or team and evidence source. A team can be accountable even when no individual owner is recorded. |
| `workload` / `workloadType` | Optional linked application, runtime, job, or integration. |
| `permissions` | Optional strings or objects with `name` and `scope`. |
| `credentials` | Optional metadata only: identifier, type, active state, managed flag, creation/expiry/last-use times. Never include credential material. |
| `trusts` | Optional principals. Mark external trust explicitly with `external: true`. |
| `activity` | Optional events with timestamp, action, target, source, and outcome. Keep provider-native action names when possible. |
| `providerManaged` | Mark provider-owned identities so missing application-team ownership is not treated as an orphan. |

The import rejects known secret-bearing property names. It only reads the documented fields above and displays values with text rendering; it does not interpret snapshot strings as HTML.

All supplied evidence timestamps must be ISO 8601 strings containing seconds and
an explicit Z or numeric timezone. The importer rejects ambiguous local times,
impossible calendar dates, numeric epochs, and timezone offsets beyond ±14:00
instead of silently discarding that evidence.

## What the scanner flags

The local rules look for missing accountable owners, missing workload links, broad or privileged permissions, external or wildcard trust, active credentials that are expired or near expiry, active credentials without expiry, old credentials, multiple active credentials, and old or absent activity evidence.

Each identity receives a 0–100 review score. The score groups findings for triage; it is not a provider authorization decision. The row details preserve the evidence and explain each rule. “No activity” is described as an inactivity signal only when the snapshot marks the source window complete. If coverage is partial or unknown, the scanner reports that it cannot determine whether the identity is unused. An old last-seen event remains a reason to review even when collection coverage is incomplete.

## Provider data sources for future collectors

These links guide the planned collectors and show why inventory and activity coverage must be reported separately.

| Provider | Inventory / ownership / access | Activity sources and limits |
| --- | --- | --- |
| Azure / Entra ID | [Service principals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0), [service-principal owners](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-owners?view=graph-rest-1.0), and [app-role assignments](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto?view=graph-rest-1.0). Include managed identities and Azure RBAC in a later resource collector. | [Microsoft Graph sign-in logs](https://learn.microsoft.com/en-us/graph/api/resources/azure-ad-auditlog-overview?view=graph-rest-1.0) include service-principal and managed-identity sign-ins. Authentication events do not describe every downstream resource operation. |
| AWS | IAM roles, users, trust and permissions policies, access keys, and [last-used metadata](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html). Use [Access Analyzer unused-access findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html) as an additional evidence source. | [CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html) supplies API activity. Data events are not logged by default and can add cost. Role last-used metadata is not a complete event history. |
| Google Cloud | Service accounts, service agents, user-managed keys, IAM policy bindings, and workload identity federation. [List service-account keys](https://cloud.google.com/iam/docs/keys-list-get). | [Activity Analyzer](https://cloud.google.com/policy-intelligence/docs/activity-analyzer-service-account-authentication) and [Cloud Audit Logs](https://cloud.google.com/iam/docs/audit-logging) provide usage evidence. Some activity outside Google Cloud is not represented, and shared keys make workload attribution difficult. |
| Okta | OAuth service apps, scopes, service users, app assignments, and API-token lifecycle evidence. [Okta service apps](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/). | [System Log API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog) provides org events, but should not be treated as a complete history of every external API operation using a token. |

## Next implementation steps

1. Add read-only, least-privilege collectors for each provider, starting with paginated inventory and ownership data.
2. Add optional log and activity ingestion with explicit retention, freshness, and coverage reporting.
3. Correlate identities to workloads using provider resource bindings, tags, IaC metadata, and owner registries.
4. Add guided remediation exports. Keep any tenant-changing action behind a later explicit authorization and impact preview.

