# Changelog

All notable changes to this extension. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.2.3] - 2026-10-15

### Added
- VirusTotal results now include what the file did in VirusTotal's sandboxes: sandbox verdicts, Sigma behaviour rules, community YARA matches and network alerts. A sandbox calling the file malicious, a high or critical Sigma match, a YARA match or a high-severity network alert marks the file for review; lower-severity matches are shown as information.
- The toolbar icon matches the Firefox Add-ons listing.
- Store icon and screenshots, shown in the README.

### Changed
- The result dialog is light or dark as a whole, following LinkedIn's theme in chats. Before, the header stayed light while the body followed a dark system theme, leaving the header text unreadable.
- Office files are described as "Office document" instead of "ZIP".
- The popup only reports VirusTotal as on once its data sharing has been allowed.

### Fixed
- Downloading or opening a file in Google Drive more than 30 minutes after it was scanned failed with "scan has expired". The file is now scanned again.

### Security
- A LinkedIn link pasted into a message could make the extension fetch that URL with the user's cookies if it contained `?download`. Attachments are now recognised by their path only.
- Scan results for non-attachment URLs were cached by path, ignoring the query string, so two files could share a verdict. Only LinkedIn's attachment paths are cached that way now.
- When scanning a download-button card, the resulting download is matched to the card by file name instead of by timing alone.

### Pipeline
- The store upload runs in a protected `mozilla` environment that requires approval and only accepts version tags.
- GitHub Actions are pinned to full commit hashes.
- CI fails if the SBOM version differs from the manifest version; `scripts/set-version.sh` bumps both.
- Tests for the background logic run in CI.

## [0.2.2] - 2026-10-12

### Added
- Privacy policy.
- Release packages are signed with cosign (keyless) and the signature bundle is attached to each release.
- First version listed on [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/linkedin-attachment-scanner/).

### Changed
- VirusTotal lookup and Open in Google Drive ask for Firefox's built-in data-collection consent and stay off until it is granted. The manifest declares the optional data types.

## [0.2.1] - 2026-10-12

### Security
- Profile, company and similar links are told apart from attachments by their URL path only (CodeQL "missing regular expression anchor").

### Added
- Security policy, CODEOWNERS, and issue and pull request templates.

### Changed
- GitHub Actions updated to their current major versions.

## [0.2.0] - 2026-10-12

First public release.

### Added
- Local scanning of LinkedIn message attachments: Office macros and remote templates, legacy Office exploits, PDF scripts and actions, RTF objects, disguised executables, archives, and HTML/SVG phishing pages.
- A status line under each attachment and a details dialog for anything that isn't clean.
- A safety net that pauses, scans and if necessary stops every download coming from LinkedIn.
- Optional VirusTotal lookup by SHA-256 fingerprint.
- Optional Open in Google Drive, to view a file in Google's viewer instead of on the computer.
- CI, security scanning (Gitleaks, Trivy, CodeQL), and signed releases with SBOM and build provenance.

[0.2.3]: https://github.com/ortizjeronimo/linkedin-attachment-scanner/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/ortizjeronimo/linkedin-attachment-scanner/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/ortizjeronimo/linkedin-attachment-scanner/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ortizjeronimo/linkedin-attachment-scanner/releases/tag/v0.2.0
