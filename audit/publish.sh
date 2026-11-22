#!/usr/bin/env bash
set -u
MSG="${1:-update}"
git config user.name "audit-bot"
git config user.email "audit-bot@users.noreply.github.com"
git add results
git commit -m "$MSG [skip ci]" >/dev/null 2>&1 || true
for i in 1 2 3 4; do
  git pull --rebase --autostash origin main >/dev/null 2>&1 || true
  if git push >/dev/null 2>&1; then
    echo "pushed: $MSG"
    exit 0
  fi
  sleep 5
done
echo "push failed: $MSG"
exit 1
