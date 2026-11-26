# Threat signature updates

AegisGuard can download a public list of known-malware SHA-256 hashes so detection improves without a new release.

## Setup (once)
1. Create a free account at https://auth.abuse.ch and copy your **Auth-Key**.
2. Store it in your user environment (never in a file in this repo):
   ```
   setx ABUSECH_AUTH_KEY "your-key-here"
   ```
   Sign out and back in (or reopen PowerShell) so programs see it.
3. Download the list:
   ```
   aegisguard update-signatures
   aegisguard update-signatures --status
   ```

The background monitor refreshes the list every 6 hours when a key is set (and silently skips it when not).
The provider asks for at most one download per hour; AegisGuard enforces that (`--force` overrides it for testing).

## Notes
- Feed hashes go in `data\threat_feed.txt`; your own entries in `data\threat_hashes.txt` take precedence.
- A different feed can be used by changing `signature_feed_url` in `data\settings.json` (must be HTTPS; use
  `{auth_key}` in the URL where the key belongs).
- A hash match only means a file is byte-for-byte identical to a known sample. New or modified malware is caught by
  the heuristics instead, so this is a supplement, not a replacement.
- Check abuse.ch's terms of use before redistributing any data from their feeds.
