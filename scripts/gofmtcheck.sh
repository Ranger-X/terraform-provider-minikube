#!/usr/bin/env bash

set -euo pipefail

# Importing kubernetes deps
# https://github.com/kubernetes/kubernetes/issues/79384#issuecomment-521493597
#VERSION=${1#"v"}
#if [ -z "$VERSION" ]; then
#    echo "Must specify version!"
#    exit 1
#fi
#echo "==> Importing kubernetes ${VERSION} packages..."
#MODS=($(
#    curl -sS https://raw.githubusercontent.com/kubernetes/kubernetes/v${VERSION}/go.mod |
#    sed -n 's|.*k8s.io/\(.*\) => ./staging/src/k8s.io/.*|k8s.io/\1|p'
#))
#for MOD in "${MODS[@]}"; do
#    V=$(
#        go mod download -json "${MOD}@kubernetes-${VERSION}" |
#        sed -n 's|.*"Version": "\(.*\)".*|\1|p'
#    )
#    go mod edit "-replace=${MOD}=${MOD}@${V}"
#done
#go get "k8s.io/kubernetes@v${VERSION}"

# Check gofmt
echo "==> Checking that code complies with gofmt requirements..."
gofmt_files=$(gofmt -l `find . -name '*.go' | grep -v vendor`)
if [[ -n ${gofmt_files} ]]; then
    echo 'gofmt needs running on the following files:'
    echo "${gofmt_files}"
    echo "You can use the command: \`make fmt\` to reformat code."
    exit 1
fi

exit 0
