#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
find app -name '*.lua' -print0 | xargs -0 -n1 luac5.1 -p
for script in app/static/*.js; do node --check "$script"; done
LUA_PATH='app/modules/?.lua;;' busted --lua=lua5.1 --pattern='test_.*%.lua' app/tests
npm test
npm run test:browser
# Container runners may use a different UID from the checkout owner. Trust only
# this checkout for this command; do not weaken Git's global ownership checks.
git -c safe.directory="$PWD" diff --check
