#!/usr/bin/env bash
# Fails if the repository references other gateway products or vendors by name.
set -euo pipefail
cd "$(dirname "$0")/.."
pattern='lite[-_ ]?llm|berri'
if git ls-files --cached --others --exclude-standard | grep -v -E '^(web/node_modules/|PLAN\.md$)' \
   | xargs grep -n -i -E "$pattern" 2>/dev/null | grep -v 'scripts/lint-brand.sh'; then
  echo "lint-brand: forbidden references found" >&2
  exit 1
fi
echo "lint-brand: ok"
