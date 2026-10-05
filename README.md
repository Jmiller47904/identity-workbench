# Identity Workbench

Inspect JWT and SAML 2.0 responses locally. Decode claims, compare expected audience/issuer/recipient, inspect time conditions, and get Entra-specific diagnostic clues. This is an inspection tool, not a token validator: it does not verify signatures, trust, replay protection, or full protocol validity.

## Current capabilities

| Capability | Status |
| --- | --- |
| Local JWT/SAML inspection and Entra diagnostic clues | Available in the browser and desktop interface |
| Graph request/JSON builder, permission and impact previews, PowerShell/cURL export | Available as an offline Node.js CLI/library developer preview |
| B2B guest UPN targets, including encoded `#EXT#` identifiers | Supported by the Graph profile-update template |
| Graph builder browser integration and searchable Entra attributes/claims reference | Planned |
| Authenticated Graph execution and tenant response diagnostics | Planned |

The default branch can contain changes newer than published downloads. The Graph
CLI/library is source-only and is not bundled in the current Electron packaging.
Check [Releases](https://github.com/Jmiller47904/identity-workbench/releases) for
published downloads and their version; a merged change does not automatically
update an existing release.

## Recent updates

- **October 5, 2026 — B2B Graph targets:** the profile-update builder accepts guest
  `#EXT#` UPNs and encodes identifiers as a single path segment, including
  apostrophes. Added regression coverage. [PR #3](https://github.com/Jmiller47904/identity-workbench/pull/3).
- **October 2026 — Offline Graph builder:** added documented `get-me` and
  `update-user-profile` templates, local JSON checks, permission/impact previews,
  and PowerShell/cURL exports with focused tests. [PR #2](https://github.com/Jmiller47904/identity-workbench/pull/2).
  This increment does not execute requests or provide browser Graph controls.
- **October 2026 — Expanded product direction:** established the daily analyst
  companion roadmap, feature priorities, and longer-term module/product boundaries.

## Use it

- Offline: open `Identity-Workbench-Offline.html` in a modern browser. No installation or connection is needed for inspection.
- Desktop: Windows Setup and Portable executables, macOS DMG, and Linux AppImage are produced by the downloadable-clients workflow. These binaries are not included in the source archive until built. The desktop app bundles the complete interface locally; it does not load the hosted site.

The input stays in page memory. No analytics, token uploads, token history, or browser storage. Documentation links open externally only when clicked. Clearing input or closing the window clears the application's in-memory results. The operating system may manage memory, crash dumps, or clipboard contents separately.

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
3. The **Publish browser app** workflow tests and deploys `web-release/` on each push to `main`. Relative paths support repository subpaths.
4. The **Build downloadable clients** workflow runs on pushes to main, version tags, or manual runs. After all builds pass, it publishes the package version as a GitHub Release if that version does not already exist. Existing releases are never overwritten. Bump package.json and the lockfile version before publishing updated release assets.

GitHub Pages workflow reference: https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages

Desktop packages are unsigned unless code signing is configured. Windows/macOS can show publisher warnings. macOS builds are not notarized. No automatic updater or updater signing bypass is included. Use a trusted release; do not disable OS protections globally.

## Scope and limits

Supports raw JWT (including Bearer prefix), raw SAML XML, Base64 SAML, and SAMLResponse form values. Encrypted JWE/SAML and multiple assertions are rejected. Time checks use the device clock with no skew allowance. SAML inspection is namespace-aware but does not implement full schema or profile validation. Token claims remain untrusted even if expected strings match.

Synthetic examples contain no real identities or credentials. Never commit production tokens to examples, tests, issues, or build logs.

## Offline Graph request builder (developer preview)

This first Graph increment is a dependency-free CLI and reusable CommonJS library;
there are no Graph controls in the browser/desktop interface yet. No requests are
sent and no credentials are accepted or saved. Node.js is required.

Save a synthetic `request.json`:

```json
{"template":"update-user-profile","userId":"demo@example.com","body":{"department":"Identity","jobTitle":"Analyst"}}
```

Run `node scripts/graph-request.cjs request.json` for a request/permission/impact
preview. Add `powershell` or `curl` to print a command for explicit review and later
execution. Output may contain your supplied profile data; redirect/save it only
intentionally. Use synthetic data in shared examples. The CLI never executes exports.
The cURL export targets POSIX shells; authenticate separately for either export.

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

Next: browser integration and a searchable attributes/claims reference, followed
by explicitly authenticated testing. See roadmap issue #1.

## Roadmap

The next increments are browser integration for the Graph builder, a searchable
Entra attributes/claims reference, and explicitly authenticated Graph testing.
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

<iframe width="560" height="315" src="https://www.youtube.com/embed/Y99kOgiXmRc?si=8QtXVajLUJ-LTqka" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
