# Identity Workbench

Inspect JWT and SAML 2.0 responses locally. Decode claims, compare expected audience/issuer/recipient, inspect time conditions, and get Entra-specific diagnostic clues. This is an inspection tool, not a token validator: it does not verify signatures, trust, replay protection, or full protocol validity.

## Current capabilities

| Capability | Status |
| --- | --- |
| Local JWT/SAML inspection and Entra diagnostic clues | Available in the browser and desktop interface |
| Local OAuth/OIDC authorization-error response diagnosis | Available in the browser and desktop UI |
| Graph request/JSON builder, permission and impact previews, PowerShell/cURL export, local response explanations | Available in the browser, desktop UI, and offline Node.js CLI/library |
| B2B guest UPN targets, including encoded `#EXT#` identifiers | Supported by the Graph profile-update template |
| Searchable Entra attributes/claims reference in browser and desktop UI | Available (curated starting set) |
| Authenticated Graph execution and tenant response diagnostics | Planned |

The default branch can contain changes newer than published downloads. The Graph
request builder is bundled in the browser and desktop source, and its CLI remains available.
The latest published download is [v0.2.0](https://github.com/Jmiller47904/identity-workbench/releases/tag/v0.2.0),
published September 5, 2026: Windows Setup/Portable, macOS DMGs (x64 and arm64),
Linux AppImage, and standalone offline HTML. It predates the October Graph builder, B2B target changes, and browser workbench; those require the current source checkout. A merged change
does not automatically update an existing release.

## Recent updates

- **October 31, 2026 — local OAuth/OIDC error diagnostics:** recognizes authorization error callbacks and OAuth error JSON, surfaces documented error and correlation fields, and can compare returned state locally. Successful callback codes and token responses are rejected. It does not authenticate or send requests. [PR #8](https://github.com/Jmiller47904/identity-workbench/pull/8).

- **October 31, 2026 — browser Graph workbench:** brings the existing offline templates into the browser and desktop UI for local request previews, JSON, PowerShell, and cURL exports, and adds a local explainer for pasted Graph status/body data. It sends no requests and does not accept credentials. [PR #7](https://github.com/Jmiller47904/identity-workbench/pull/7).

- **October 31, 2026 — searchable Entra reference:** adds a local cross-reference for eight common Graph user properties and related token claims. It distinguishes documented relationships from properties with no guaranteed direct claim mapping and links each entry to Microsoft Learn. The curated reference does not predict tenant output or validate tokens. [PR #6](https://github.com/Jmiller47904/identity-workbench/pull/6).

- **October 19, 2026 — strict SAML time syntax (proposed):** SAML conditions
  reject impossible calendar dates and timezone-ambiguous timestamps instead of
  relying on JavaScript's permissive date normalization. Valid inspected values
  must use the supported XML `dateTime` form with `Z` or a numeric timezone.
  The same PR adds browser/offline and cross-platform desktop packaging checks
  for pull requests while explicitly skipping Pages deployment and releases.
  [PR #5](https://github.com/Jmiller47904/identity-workbench/pull/5). This is an
  unmerged source change and is not present in v0.2.0 release assets.
- **October 12, 2026 — JWT time diagnostics:** malformed numeric dates that
  overflow JavaScript's finite number range are reported only as invalid claims;
  they are no longer also described as future or otherwise valid time values.
  [PR #4](https://github.com/Jmiller47904/identity-workbench/pull/4).
- **October 5, 2026 — B2B Graph targets:** the profile-update builder accepts guest
  `#EXT#` UPNs and encodes identifiers as a single path segment, including
  apostrophes. Added regression coverage. [PR #3](https://github.com/Jmiller47904/identity-workbench/pull/3).
- **October 1, 2026 — Offline Graph builder:** added documented `get-me` and
  `update-user-profile` templates, local JSON checks, permission/impact previews,
  and PowerShell/cURL exports with focused tests. [PR #2](https://github.com/Jmiller47904/identity-workbench/pull/2).
  This increment does not execute Graph requests; browser controls are available in the workbench described above.
- **October 2026 — Expanded product direction:** established the daily analyst
  companion roadmap, feature priorities, and longer-term module/product boundaries.

## Use it

- Offline: download `Identity-Workbench-Offline.html` from [v0.2.0 release assets](https://github.com/Jmiller47904/identity-workbench/releases/tag/v0.2.0) and open it in a modern browser. For the current source version, run `npm run build:web` and open `web-release/Identity-Workbench-Offline.html`; the generated HTML is not included in the source checkout. No installation or connection is needed for inspection once the HTML is saved.
- Desktop: Windows Setup and Portable executables, macOS DMG, and Linux AppImage are produced by the downloadable-clients workflow. These binaries are not included in the source archive until built. The desktop app bundles the complete interface locally; it does not load the hosted site.

The input stays in page memory. No analytics, token uploads, token history, or browser storage. Documentation links open externally only when clicked. Clearing input or closing the window clears the application's in-memory input, expected values, and results. The operating system may manage memory, crash dumps, or clipboard contents separately.

## Development

Requires Node.js 22.13 or newer. Run `npm ci`, then `npm test`.

- `npm run build:web`: create the static browser site and standalone HTML client in `web-release/`.
- `npm run desktop`: launch the Electron client.
- `npm run build:windows`: build Windows x64 Setup and Portable executables on Windows.
- `npm run desktop:dist -- --mac`: build macOS on a Mac.
- `npm run desktop:dist -- --linux`: build Linux on Linux.

Dependencies are pinned and the lockfile is committed. Electron uses sandboxing, context isolation, no Node access in the renderer, no preload/IPC bridge, an in-memory session, denied permissions, and a local asset allowlist. Renderer navigation and arbitrary external links are blocked. See https://www.electronjs.org/docs/latest/tutorial/security.

## GitHub deployment

1. Create or select the GitHub repository and push this source to `main`.
2. In Settings → Pages, select **GitHub Actions** as the publishing source. Check the site's intended audience; GitHub Pages access is separate from source-repository visibility.
3. The **Publish browser app** workflow tests browser/offline builds on pull requests and deploys `web-release/` only after a push to `main` or an explicit manual run. Relative paths support repository subpaths.
4. The **Build downloadable clients** workflow packages Windows, macOS and Linux clients on pull requests, pushes to main, version tags, or manual runs. Pull requests upload review artifacts but never publish a release. For non-PR runs, after all builds pass, it publishes the package version as a GitHub Release if that version does not already exist. Existing releases are never overwritten. Bump package.json and the lockfile version before publishing updated release assets.

GitHub Pages workflow reference: https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages

Desktop packages are unsigned unless code signing is configured. Windows/macOS can show publisher warnings. macOS builds are not notarized. No automatic updater or updater signing bypass is included. Use a trusted release; do not disable OS protections globally.

## Scope and limits

Supports raw JWT (including Bearer prefix), raw SAML XML, Base64 SAML, SAMLResponse form values, and OAuth/OIDC error callbacks or JSON error objects. The OAuth/OIDC view rejects successful responses containing authorization codes or tokens; it does not authenticate or follow error URIs. It displays provider error descriptions as untrusted developer text and never uses them as a programmatic error key. An optional state comparison checks exact strings locally; it does not establish CSRF protection or validate a complete authentication flow. Encrypted JWE/SAML and multiple assertions are rejected. JWT time claims must decode to finite numeric seconds; malformed or overflowing values are not evaluated as valid dates. SAML condition times use a strict supported subset of XML `dateTime`: a four-digit year, real calendar date, seconds, optional fractional seconds, and explicit `Z` or numeric timezone (up to ±14:00). Time checks use the device clock with no skew allowance. SAML inspection is namespace-aware but does not implement full schema or profile validation. Recipient comparison treats multiple SubjectConfirmation elements as alternatives: at least one inspected recipient must match. This is a configuration clue only; the tool does not establish that the matching confirmation passes its method, time, signature, response-correlation, or other profile checks. Token claims remain untrusted even if expected strings match.

Synthetic examples contain no real identities or credentials. Never commit production tokens to examples, tests, issues, or build logs.

OAuth/OIDC error handling verified October 31, 2026:
- [Microsoft identity platform authorization-code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow): authorization errors can be returned to the redirect URI with error details; when state was sent, the client should verify the returned state.
- [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes): use the error code to classify failures; error descriptions and trace/correlation fields support developer diagnostics.

## Graph request workbench (offline preview)

The browser and desktop workbench use the same request templates and validation
functions as the dependency-free Node.js CLI/library. The UI can preview documented
requests and export JSON, PowerShell, or cURL text. It does not execute requests,
accept credentials, or save tokens or secrets. The Graph builder requires no network
access; the application Content Security Policy blocks connections.

Save a synthetic `request.json`:

```json
{"template":"update-user-profile","userId":"demo@example.com","body":{"department":"Identity","jobTitle":"Analyst"}}
```

Run `node scripts/graph-request.cjs request.json` for the same request/permission/impact
preview as the UI. Add `powershell` or `curl` to print a command for explicit review and
later execution. Output may contain your supplied profile data; redirect/save it only
intentionally. Use synthetic data in shared examples. Neither the CLI nor UI executes exports.
The cURL export targets POSIX shells; authenticate separately for either export.

The same workbench includes an offline response explainer. Paste an HTTP status,
optional Retry-After value, and JSON response body to see general guidance for
common errors, throttling, and responses containing @odata.nextLink. It never
retries a request or follows a next-page URL. For paging, Microsoft recommends
using the full @odata.nextLink URL as returned; required custom headers may need
to be supplied again on subsequent directory-page requests. For HTTP 429, honor
Retry-After; if it is absent, Microsoft recommends exponential backoff. A 403
can also mean the signed-in user lacks access even when the application has been
granted a permission. These are general explanations, not tenant-specific diagnosis.

Response bodies can contain identity data. The explainer processes pasted values
only in page memory; clear the response or close the window when finished. No
response is uploaded, saved, or logged.

`get-me` supports delegated access and optional `select` fields: `id`, `displayName`,
`userPrincipalName`, `department`, `jobTitle`. `update-user-profile` supports only
nonempty string changes to `department` and `jobTitle`; null/clear operations,
other properties, beta, sovereign clouds and arbitrary endpoints are outside this
preview. User targets accept a standard Entra object ID or UPN, including B2B
`#EXT#` UPNs; the path segment is encoded according to the linked Graph guidance.
UPNs beginning with `$` remain outside this preview because Microsoft documents a
different OData parenthesized syntax for them. Local validation is a narrow template check, not complete Graph schema,
permission, domain, tenant, or dry-run validation.

Sources verified October 5, 2026:
- [Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0): `/me` uses delegated `User.Read`.
- [Update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0): the other-user profile template lists `User.ReadUpdate.All`; caller privileges, consent and synchronization/source-of-authority restrictions still apply.

Response guidance verified October 31, 2026:
- [Microsoft Graph error responses](https://learn.microsoft.com/en-us/graph/errors): structured errors include an error code and message; use them with the HTTP status and request ID when available.
- [Microsoft Graph throttling](https://learn.microsoft.com/en-us/graph/throttling): honor Retry-After for HTTP 429; if absent, use exponential backoff and avoid immediate retries.
- [Microsoft Graph paging](https://learn.microsoft.com/en-us/graph/paging): use the complete @odata.nextLink URL as an opaque value; custom headers other than Authorization and Content-Type aren't carried to subsequent requests by default.

Next: explicitly authenticated testing with tenant/account identification, least-privilege guidance, and an impact preview before mutations. The searchable Entra reference is available as a curated starting set; broader coverage remains planned. See roadmap issue #1.

## Roadmap

The offline Graph builder is available in the browser and desktop source. The next
increment is explicitly authenticated Graph testing, requiring tenant/account identification,
least-privilege guidance, and an impact preview before mutations. The searchable Entra reference is available as a curated starting set and needs broader, continuously verified coverage.
Later analyst workflows cover app registrations/service principals, roles/consent,
federation, SCIM/provisioning, certificates, Conditional Access, sign-in diagnostics,
token comparison, and explicitly saved sanitized case workspaces.

Long-term ideas are exploratory; they are not implemented or committed releases.

| Direction | Exploratory capabilities |
| --- | --- |
| Core Workbench modules | Enterprise Identity Doctor, Identity Integration Autopilot, Access Decision Engine |
| Modules first; optional services at scale | Machine/AI Identity Governance, Certificate Dependency Autopilot |
| Platform extensions/shared capabilities | Third-Party Exposure Graph, Institutional Knowledge Compiler |
| Companion or separate product candidates | Enterprise AI Data Firewall, Compliance-to-Remediation Engine, Production Incident Investigator, SaaS Spend Autopilot |

Keep a capability in Workbench when its primary user and evidence are centered on
identity analysis. Consider a separate application/service when it requires
continuous runtime enforcement, broad non-identity data, or a different operating
team. Reuse shared connectors and evidence models across products.

See [the central roadmap and detailed scope](https://github.com/Jmiller47904/identity-workbench/issues/1)
and [October feature priorities](docs/FEATURE_PRIORITIES_2026-10.md).

## Keeping this README current

Changes that affect users or contributors should update this README in the same
pull request: capabilities, usage examples, setup/build commands, permissions,
security behavior, limitations, compatibility, and roadmap status. Record meaningful
updates with a date and a linked PR or release; omit routine internal churn.

Describe default-branch capabilities separately from published release assets.
Keep planned work labeled as planned and developer previews labeled with their
actual supported interfaces. Preserve official documentation sources and verification
dates for Graph templates. Never include credentials, raw production tokens, or
tenant-sensitive examples.

Weekly maintenance and monthly feature work should include a documentation pass.
