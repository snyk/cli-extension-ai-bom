#!/bin/bash

CLI_PATH="${1:-../cli}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_PATH="$(cd "${SCRIPT_DIR}/.." && pwd)"

# go.mod files that may contain the replace statement. Go only honors replace
# directives from the main module, which is cliv2-private when it is present
# (BUILD_MODE=private is auto-detected), so both need to be uncommented.
GO_MODS=("${CLI_PATH}/cliv2/go.mod" "${CLI_PATH}/cliv2-private/go.mod")
UNCOMMENTED_GO_MODS=()

cleanup() {
  for go_mod in "${UNCOMMENTED_GO_MODS[@]}"; do
    if grep -q "^[[:space:]]*replace github.com/snyk/cli-extension-ai-bom => ${REPO_PATH}$" "$go_mod"; then
      perl -i -pe "s|^(\\s*)replace github.com/snyk/cli-extension-ai-bom => ${REPO_PATH}\$|\1// replace github.com/snyk/cli-extension-ai-bom => ../../cli-extension-ai-bom|" "$go_mod"
      printf "\nRestored replace statement in %s" "$go_mod"
    fi
  done
}

trap cleanup EXIT

if [ ! -d "$CLI_PATH" ]; then
  echo "Error: CLI path '$CLI_PATH' does not exist. Clone it from https://github.com/snyk/cli to the parent directory."
  exit 1
fi

# Uncomment the replace statement for cli-extension-ai-bom. This allows building the local extension with the local CLI.
# Uses perl for cross platform compatibility.
for go_mod in "${GO_MODS[@]}"; do
  [ -f "$go_mod" ] || continue
  if grep -q "^[[:space:]]*//[[:space:]]*replace github.com/snyk/cli-extension-ai-bom => ../../cli-extension-ai-bom" "$go_mod"; then
    perl -i -pe "s|^(\\s*)//\\s*replace github.com/snyk/cli-extension-ai-bom => ../../cli-extension-ai-bom|\1replace github.com/snyk/cli-extension-ai-bom => ${REPO_PATH}|" "$go_mod"
    echo "Uncommented replace statement in $go_mod (pointing to ${REPO_PATH})"
    UNCOMMENTED_GO_MODS+=("$go_mod")
  fi
done

BINARY_PATH=$(
  cd ${CLI_PATH} || exit 1
  make build 2>&1 | tee /dev/tty | grep -o '/.*binary-releases/[^ )]*' | head -1 | tr -d '[:space:]'
)

echo "Binary path: $BINARY_PATH"
echo "You can test the cli by running: $BINARY_PATH. Feel free to make a symlink."

