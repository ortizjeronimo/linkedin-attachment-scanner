#!/usr/bin/env bash
# Sets the extension version everywhere it is recorded, so the manifest and the SBOM can't drift.
# Usage: scripts/set-version.sh 0.2.3
set -euo pipefail

version="${1:-}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 <major.minor.patch>" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

# The extension's own version is the first "version" key in the manifest.
sed -i -E "0,/\"version\": \"[^\"]*\"/s//\"version\": \"${version}\"/" src/manifest.json
# In the SBOM, only the component named after the project carries it (Trivy's own version is left alone).
sed -i -E "/\"name\": \"linkedin-attachment-scanner\"/{n;s/\"version\": \"[^\"]*\"/\"version\": \"${version}\"/}" sbom.cdx.json

grep -n "\"version\": \"${version}\"" src/manifest.json sbom.cdx.json
