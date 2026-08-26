# Releasing

## Private beta (current)

Collaborators install with:

```bash
gh release download v0.1.0-beta.1 -R aalises/dalekohled -p '*aarch64*' -O - | tar -xz
```

or `cargo install --git https://github.com/aalises/dalekohled`.

To cut a new beta: build locally, `tar -czf`, and `gh release create vX.Y.Z-beta.N <tarball> --prerelease`.
Note: any `v*` tag push now triggers `.github/workflows/release.yml` (dist), which builds all
targets in CI and attaches them to the release automatically — so `gh release create` with just
notes (no local tarball) is enough once CI is green.

## Public launch checklist

1. **Scrub the demo.** `demo.gif`/`demo.mp4` show real session previews. Re-record against a staged
   `$HOME` with fixture sessions (`HOME=/tmp/demo-home vhs demo.tape`), or curate the filters in
   `demo.tape`. Skim every frame before publishing.
2. **Check history.** The git history is clean (code + docs only), but do a final
   `git log -p | grep -iE 'token|secret|key'` pass.
3. **Make the repo public.** GitHub → Settings → Danger Zone.
4. **Tag `v0.1.0`.** dist CI builds macOS (arm/x64), Linux (arm/x64), Windows, and attaches:
   - `cxwatch-installer.sh` → users run `curl -fsSL https://github.com/aalises/dalekohled/releases/latest/download/cxwatch-installer.sh | sh`
   - a Homebrew formula artifact and an npm package artifact.
5. **Optional publishing** (each needs one-time setup):
   - **Homebrew tap**: create public repo `aalises/homebrew-tap`, add `tap = "aalises/homebrew-tap"`
     and `publish-jobs = ["homebrew"]` under `[dist]`, and a `HOMEBREW_TAP_TOKEN` repo secret
     (a PAT with write access to the tap). Then `brew install aalises/tap/cxwatch` works.
   - **npm**: reserve the package name, add an `NPM_TOKEN` secret and `publish-jobs = ["npm"]`.
     Then `npx cxwatch` works.
   - **crates.io**: `cargo publish` (name claim is permanent — decide the name first).
6. **Announce** with the demo mp4.
