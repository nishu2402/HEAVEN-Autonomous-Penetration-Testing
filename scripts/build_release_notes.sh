#!/usr/bin/env bash
# Build the GitHub Release notes for HEAVEN.
#
# The notes are, in order:
#   1. The dynamic banner — the hero poster (a theme-aware <picture>) plus the
#      shield badge rows, lifted straight from README.md so the banner is ALWAYS
#      in sync with the project's current numbers (scripts/sync_test_count.py keeps
#      the README poster + badges current every release). The poster's relative
#      image paths are rewritten to tag-pinned raw URLs so they resolve on the
#      Release page and freeze that release's numbers to that tag forever.
#   2. This version's CHANGELOG.md section.
#   3. The install + pre-trained-model instructions.
#
# This is the single source of truth for release-note formatting: the release
# workflow (.github/workflows/release.yml) calls it, and a maintainer can run it
# by hand for a manual release. That is what guarantees EVERY release carries the
# same banner.
#
# Usage:
#   scripts/build_release_notes.sh <version> [tag] [owner/repo] > notes.md
#   # e.g. scripts/build_release_notes.sh 4.2.0
#   #      scripts/build_release_notes.sh 4.2.0 v4.2.0 nishu2402/HEAVEN-Autonomous-Penetration-Testing
set -euo pipefail

VERSION="${1:?usage: build_release_notes.sh <version> [tag] [owner/repo]}"
TAG="${2:-v$VERSION}"
REPO="${3:-${GITHUB_REPOSITORY:-nishu2402/HEAVEN-Autonomous-Penetration-Testing}}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README="$HERE/README.md"
CHANGELOG="$HERE/CHANGELOG.md"
RAW="https://raw.githubusercontent.com/$REPO/$TAG/docs/assets"

# 1) Banner: the README header block — from the poster's <p align="center"> down
#    to the </div> that closes the badge rows — with the poster's relative
#    docs/assets/ paths rewritten to tag-pinned absolute raw URLs. The standalone
#    "---" rule between the poster and the badges is dropped so they render as one
#    contiguous banner (as on the Release page). The shield URLs are already
#    absolute https://img.shields.io/... links and are emitted unchanged, so the
#    live Tests / Release badges stay live.
awk '/<p align="center">/{f=1} f{print} f && /<\/div>/{exit}' "$README" \
  | sed "s#docs/assets/#$RAW/#g" \
  | grep -vx -- '---'

# 2) This version's changelog section (everything between "## [<ver>]" and the
#    next "## [" heading).
awk -v ver="$VERSION" '
  $0 ~ "^## \\[" ver "\\]" {flag=1; next}
  flag && /^## \[/ {exit}
  flag {print}
' "$CHANGELOG" > /tmp/_hv_changelog_body.md || true
if [ -s /tmp/_hv_changelog_body.md ]; then
  cat /tmp/_hv_changelog_body.md
else
  echo ""
  echo "See [CHANGELOG.md](https://github.com/$REPO/blob/$TAG/CHANGELOG.md) for changes."
fi
rm -f /tmp/_hv_changelog_body.md

# 3) Install + pre-trained-model instructions.
cat <<EOF

### Install

HEAVEN is distributed here, not on PyPI. Install the attached wheel:

\`\`\`bash
pip install heaven_pentest-${VERSION}-py3-none-any.whl
\`\`\`

…or from source: \`git clone\` + \`pip install -e .\` (or the one-command
\`./scripts/install.sh\`).

### Pre-trained NVD CVSS model

The ML CVSS model (R²≈0.99) ships as a release asset, not in the wheel. Fetch it
once (SHA-256 verified):

\`\`\`bash
heaven download-model --tag ${TAG}
\`\`\`

HEAVEN runs without it (CVSS falls back to each finding's base score).
EOF
