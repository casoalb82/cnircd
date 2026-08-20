#!/bin/bash
# Rebase ChatNet's patches (see README.chatnet.md) onto the latest
# upstream Solanum. Run from the repo root. Stops for you to resolve
# by hand if a patch no longer applies cleanly -- it will not force
# anything or lose your local changes.
set -e

UPSTREAM_URL="https://github.com/solanum-ircd/solanum.git"
FIRST_CHATNET_COMMIT=$(git log --format="%H" --grep="^Drop arc4random_stir" | tail -1)

if [ -z "$FIRST_CHATNET_COMMIT" ]; then
	echo "Couldn't find the first ChatNet patch commit -- has the repo history changed?" >&2
	exit 1
fi

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM_URL"
echo "Fetching upstream..."
git fetch upstream

BASE=$(git rev-parse "${FIRST_CHATNET_COMMIT}^")
echo "Current base: $BASE"
echo "Rebasing ChatNet patches onto upstream/master..."

git rebase --onto upstream/master "$BASE"

echo
echo "Done. Review with 'git log --oneline' and 'git diff origin/main', then:"
echo "  git push --force-with-lease origin main"
