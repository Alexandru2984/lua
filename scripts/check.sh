#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
find app -name '*.lua' -print0 | xargs -0 -n1 luac5.1 -p
for script in app/static/*.js; do node --check "$script"; done
LUA_PATH='app/modules/?.lua;;' busted --lua=lua5.1 --pattern='test_.*%.lua' app/tests
npm test
npm run test:browser
git diff --check
