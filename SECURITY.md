# Security Policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report them privately through **Security → Report a vulnerability** on this repository ([direct link](https://github.com/ortizjeronimo/linkedin-attachment-scanner/security/advisories/new)). Include:

- what the problem is and what an attacker gains from it
- steps or a sample file that reproduces it (for malicious samples, a description or a hash is enough; don't attach live malware)
- the extension version and Firefox version

You can expect an acknowledgement within a week. Once a fix is released, the advisory is published and you are credited unless you ask not to be.

## What counts

- A file with a known red flag (macros, scripts, a disguised executable and so on) that the scanner reports as "No threats found".
- A file that makes the scanner crash, hang, or let a download through unscanned.
- Anything that lets a web page or a message sender make the extension act outside its purpose, such as reading data, making requests, or running code.

A brand-new malware technique that the heuristics simply don't know about is a detection gap, not a vulnerability. Those are welcome as ordinary issues or pull requests.

## Verifying a release

Release packages are built by GitHub Actions and carry signed build provenance:

```
gh attestation verify linkedin_attachment_scanner-<version>.zip --repo ortizjeronimo/linkedin-attachment-scanner
```

Each release also includes `SHA256SUMS` and a CycloneDX SBOM.
