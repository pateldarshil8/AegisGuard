# How updates work

## For you (the developer)
1. Change code, commit, `git push` to `main`.
2. GitHub Actions (`.github/workflows/release.yml`) runs the tests, builds the installer and publishes a Release:
   first build is `1.0.0`, then `1.0.1`, `1.0.2`, ... (the patch number counts up automatically).
   Pushes that only touch `*.md` or `docs/` don't trigger a build.
3. To start a new line (e.g. `1.1.x` or `2.0.x`), change `__version__` in `src/aegisguard/__init__.py` and
   `version` in `pyproject.toml`.
4. Watch the build under the repo's **Actions** tab. If tests fail, nothing is released.

## For users
- When AegisGuard opens it checks for a newer release and shows an **Update available** popup
  (*Install now / Later / Skip this version*). Opened hidden at sign-in, you get a tray notification instead.
- While running, it re-checks every ~6 hours; a new version adds a dot to the **Updates** tab and a tray notification.
- Installing downloads the installer, verifies its SHA-256 against the checksum published with the release,
  closes AegisGuard, runs the installer silently (Windows asks for administrator permission) and restarts it in the tray.
- `aegisguard update` / `aegisguard update --install` do the same from the command line.
- Turn automatic checks off with `"check_updates": false` in `data\settings.json`.

## First time only
The very first updater-enabled build has to be installed by hand (older installs don't contain the updater).

## Security notes
HTTPS + GitHub hosts only, a release without a checksum file is never offered, oversized downloads are rejected,
the file is re-hashed right before running. Updates are as trustworthy as your GitHub account (turn on 2FA), and
code-signing the installer would add a second layer.
