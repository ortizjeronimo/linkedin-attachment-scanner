# Privacy Policy

_LinkedIn Attachment Scanner, a Firefox extension. Last updated: 12 October 2026._

## Summary

The extension checks files on your own computer. It has no server, no analytics and no tracking, and its author receives no data from it. Data leaves your device only through two optional features that are off until you set them up, and only to the service you chose.

## What happens on your device

- When a file appears in a LinkedIn conversation, or a download starts from LinkedIn, the extension fetches that file from LinkedIn using your existing LinkedIn session and analyses it locally in the browser.
- A list of recent scans (file name, size, verdict, SHA-256 fingerprint and time, up to 50 entries) is kept in the browser's local extension storage so the toolbar popup can show it. You can clear it from the popup. It is removed when you uninstall the extension.
- Your settings, including any VirusTotal API key or Google client ID you enter, are kept in the same local storage.

None of this is sent to the author or to any third party.

## Optional features that send data off your device

Both are disabled by default. Firefox asks for your permission when you turn one on, and you can withdraw it at any time under the extension's **Permissions and data** settings.

### VirusTotal lookup

If you enter your own VirusTotal API key, the extension sends the **SHA-256 fingerprint** of each scanned file, together with your API key, to `www.virustotal.com` to ask whether the file is known. The file itself, its name and its contents are never sent. VirusTotal's handling of the request is covered by [VirusTotal's privacy policy](https://docs.virustotal.com/docs/privacy-policy).

### Open in Google Drive

If you enter your own Google OAuth client ID and click **Open in Google Drive** on a scan result, the extension:

- opens a Google sign-in window so you can grant it permission to add files to your Drive (the `drive.file` scope, which only covers files the extension itself uploaded);
- uploads **that one file and its name** to your own Google Drive, and opens it in Google's viewer.

A file is uploaded only when you click the button for it. The uploaded file stays in your Drive until you delete it. The access token Google returns is held in memory only and is not stored. Google's handling of the file is covered by [Google's privacy policy](https://policies.google.com/privacy).

## What the extension does not do

- It does not read your LinkedIn messages, contacts or profile. It only looks for attachment cards and download links in the page so it can scan the files behind them.
- It does not collect browsing history, identifiers, usage statistics or crash reports.
- It does not sell or share data with anyone.

## Permissions

| Permission | Why it is needed |
|---|---|
| Access to `linkedin.com` and `licdn.com` | Find attachments in conversations and fetch the files to scan |
| Downloads | Pause, scan, save or cancel downloads that come from LinkedIn |
| Storage | Keep your settings and the recent-scans list on your device |
| Notifications | Tell you the result of a scanned download |
| Identity and access to `googleapis.com` | Google sign-in and upload, only for the optional Drive feature |
| Access to `virustotal.com` | Fingerprint lookup, only for the optional VirusTotal feature |

## Changes and contact

Changes to this policy are published in this file in the project's repository. Questions and concerns can be raised at https://github.com/ortizjeronimo/linkedin-attachment-scanner/issues.
