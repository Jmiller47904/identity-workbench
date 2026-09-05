# Identity Workbench

Inspect JWT and SAML 2.0 responses locally. Decode claims, compare expected audience/issuer/recipient, inspect time conditions, and get Entra-specific diagnostic clues. This is an inspection tool, not a token validator: it does not verify signatures, trust, replay protection, or full protocol validity.

## Use it

- Browser: the existing private deployment is https://identity-workbench-jake.jmiller47904.chatgpt.site. GitHub Pages can host the same app after the repository is configured.
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
