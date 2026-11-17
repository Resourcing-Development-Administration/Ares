#!/usr/bin/env bash
# Extract a single version section from a CHANGELOG.md / CHANGELOG.rst.
# Usage: ./extract-changelog-section.sh [VERSION] [FILE]
# If VERSION is omitted, the first (latest) section is extracted.
# If FILE is omitted, CHANGELOG.md in the current directory is used.
set -euo pipefail

VERSION="${1:-}"
FILE="${2:-CHANGELOG.md}"

if [[ ! -f "$FILE" ]]; then
  echo "error: $FILE not found" >&2
  exit 1
fi

# Match lines that look like version headers: ## [1.2.3], ## 1.2.3, # v1.2.3, etc.
HEADER_PATTERN='^\(#\{1,3\} \)\?\(\[v\?[0-9]\|v[0-9]\|## \)'

if [[ -z "$VERSION" ]]; then
  # Extract from first header to just before the second header
  awk '/^#{1,3} (\[v?[0-9]|v[0-9])/{found++; if(found==2)exit} found>=1{print}' "$FILE"
else
  # Extract the section matching VERSION
  awk -v ver="$VERSION" '
    /^#{1,3} / && $0 ~ ver { found=1; print; next }
    found && /^#{1,3} / && $0 !~ ver { exit }
    found { print }
  ' "$FILE"
fi
