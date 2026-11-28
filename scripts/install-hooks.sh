#!/usr/bin/env bash
# Enable the repository's versioned git hooks for this clone.
#
# Records core.hooksPath in the clone's local git config (nothing global is
# touched), so `git commit` runs scripts/hooks/pre-commit, which rejects
# binaries, archives and oversized files per docs/input-policy.md.
# Hooks that may exist in the clone's private .git/hooks directory are no
# longer run afterwards; unset with:
#     git config --unset core.hooksPath
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

git -C "$root" rev-parse --is-inside-work-tree >/dev/null
[[ -x "$root/scripts/hooks/pre-commit" ]] || {
    echo "error: $root/scripts/hooks/pre-commit is missing or not executable" >&2
    exit 1
}

git -C "$root" config core.hooksPath scripts/hooks
echo "hooks enabled for $(git -C "$root" rev-parse --show-toplevel):"
echo "  pre-commit -> scripts/check_assets.py --staged"
