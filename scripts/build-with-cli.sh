#!/bin/bash

CLI_PATH="${1:-../cli}"
WAS_COMMENTED=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_PATH="$(cd "${SCRIPT_DIR}/.." && pwd)"

cleanup() {
  if [ "$WAS_COMMENTED" = true ]; then
    if grep -q "^[[:space:]]*replace github.com/snyk/cli-extension-ai-bom => ${REPO_PATH}$" ${CLI_PATH}/cliv2/go.mod; then
      perl -i -pe "s|^(\\s*)replace github.com/snyk/cli-extension-ai-bom => ${REPO_PATH}\$|\1// replace github.com/snyk/cli-extension-ai-bom => ../../cli-extension-ai-bom|" ${CLI_PATH}/cliv2/go.mod
      printf "\nRestored replace statement in ${CLI_PATH}/cliv2/go.mod"
    fi
  fi
}

trap cleanup EXIT

if [ ! -d "$CLI_PATH" ]; then
  echo "Error: CLI path '$CLI_PATH' does not exist. Clone it from https://github.com/snyk/cli to the parent directory."
  exit 1
fi 
  
# Uncomment the replace statement for cli-extension-ai-bom in cliv2/go.mod. This allows building the local extension with the local CLI.
# Uses perl for cross platform compatibility.
if grep -q "^[[:space:]]*//[[:space:]]*replace github.com/snyk/cli-extension-ai-bom => ../../cli-extension-ai-bom" ${CLI_PATH}/cliv2/go.mod; then
  perl -i -pe "s|^(\\s*)//\\s*replace github.com/snyk/cli-extension-ai-bom => ../../cli-extension-ai-bom|\1replace github.com/snyk/cli-extension-ai-bom => ${REPO_PATH}|" ${CLI_PATH}/cliv2/go.mod
  echo "Uncommented replace statement in ${CLI_PATH}/cliv2/go.mod (pointing to ${REPO_PATH})"
  WAS_COMMENTED=true
fi

BINARY_PATH=$(
  cd ${CLI_PATH} || exit 1
  make build 2>&1 | tee /dev/tty | grep -o '/.*binary-releases/[^ )]*' | head -1 | tr -d '[:space:]'
)

echo "Binary path: $BINARY_PATH"
echo "You can test the cli by running: $BINARY_PATH. Feel free to make a symlink."

