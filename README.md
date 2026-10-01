# Identity Workbench

Inspect JWT and SAML 2.0 responses locally. Decode claims, compare expected audience/issuer/recipient, inspect time conditions, and get Entra-specific diagnostic clues. This is an inspection tool, not a token validator: it does not verify signatures, trust, replay protection, or full protocol validity.

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
preview. Local validation is a narrow template check, not complete Graph schema,
permission, domain, tenant, or dry-run validation.

Sources verified October 1, 2026:
- [Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0): `/me` uses delegated `User.Read`.
- [Update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0): the other-user profile template lists `User.ReadUpdate.All`; caller privileges, consent and synchronization/source-of-authority restrictions still apply.

Next: browser integration and a searchable attributes/claims reference, followed
by explicitly authenticated testing. See roadmap issue #1.
