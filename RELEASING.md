# Releasing

## Current state: launch-ready, repo private

Everything below is done. Going public is: **Settings → make repository public**, and announce.

- ✅ **Demo scrubbed** — `demo.tape` stages a synthetic `$HOME` (`demo/fixtures.py`); recordings
  contain no real session data, with product-marketing chapter cards per act.
- ✅ **History purged** — old recordings with real session previews were removed with
  `git filter-repo`; history was force-pushed. (Collaborators: re-clone, don't pull.)
- ✅ **`v0.1.0` release staged** — the dist workflow builds macOS (arm/x64), Linux (arm/x64),
  Windows, the `cxwatch-installer.sh` one-liner, a Homebrew formula artifact and an npm package
  artifact, all attached to the (currently private) release. The moment the repo is public:

  ```bash
  curl -fsSL https://github.com/n8n-io/dalekohded/releases/latest/download/cxwatch-installer.sh | sh
  ```

## Still manual at launch (optional, ~10 min each)

- **Homebrew tap** (`brew install n8n-io/tap/cxwatch`): create public repo `n8n-io/homebrew-tap`,
  add under `[dist]` in `dist-workspace.toml`: `tap = "n8n-io/homebrew-tap"` and
  `publish-jobs = ["homebrew"]`, add a `HOMEBREW_TAP_TOKEN` repo secret (PAT with write access to
  the tap), re-tag.
- **npm** (`npx cxwatch`): reserve the package name, add `NPM_TOKEN` secret and
  `publish-jobs = ["npm"]`, re-tag.
- **crates.io**: `cargo publish` — the name claim is permanent, decide first.

## Cutting a release

Bump `version` in `Cargo.toml`, commit, then:

```bash
git tag vX.Y.Z && git push origin vX.Y.Z
```

The dist workflow builds every target and attaches all artifacts to the GitHub release.

## Private beta installs (while the repo is private)

```bash
gh release download v0.1.0 -R n8n-io/dalekohded -p '*aarch64-apple-darwin*' -O - | tar -xz
# or
cargo install --git https://github.com/n8n-io/dalekohded
```
