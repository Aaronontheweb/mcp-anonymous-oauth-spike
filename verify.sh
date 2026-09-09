#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

dotnet restore --locked-mode
dotnet build --configuration Release --no-restore
mkdir -p evidence
dotnet run --project McpAnonymousOAuth --configuration Release --no-build > evidence/observed.txt 2>&1
cat evidence/observed.txt

result=0
dotnet run --project McpAnonymousOAuth --configuration Release --no-build -- --expect-eager-auth > evidence/explicit-expectation.txt 2>&1 || result=$?
cat evidence/explicit-expectation.txt
if [[ "$result" != 1 ]]; then
    echo "Unexpected exit code for the explicit authorization expectation: $result" >&2
    exit 1
fi
grep -Fxq 'FAIL: Explicit-auth expectation: initialization and catalog discovery completed, but the SDK produced no authorization callback or token.' evidence/explicit-expectation.txt
echo "Verified: normal SDK OAuth succeeds; explicit authorization through discovery alone does not occur."
