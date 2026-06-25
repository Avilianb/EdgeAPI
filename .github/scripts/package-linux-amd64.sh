#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKSPACE="$(cd "$ROOT/.." && pwd)"
EDGE_NODE_ROOT="$WORKSPACE/EdgeNode"

VERSION="$(sed -nE 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"([0-9.]+)".*/\1/p' "$ROOT/internal/const/const.go" | head -n 1)"
NODE_VERSION="$(sed -nE 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"([0-9.]+)".*/\1/p' "$EDGE_NODE_ROOT/internal/const/const.go" | head -n 1)"

if [[ -z "$VERSION" || -z "$NODE_VERSION" ]]; then
  echo "could not detect edge-api or edge-node version" >&2
  exit 1
fi

rm -rf "$ROOT/dist" "$EDGE_NODE_ROOT/dist"

(
  cd "$EDGE_NODE_ROOT"
  bash .github/scripts/package-linux-amd64.sh
)

DIST="$ROOT/dist/edge-api"
mkdir -p "$DIST/bin" "$DIST/configs" "$DIST/logs" "$DIST/data" "$DIST/deploy" "$DIST/installers"

cp "$ROOT/build/configs/api.template.yaml" "$DIST/configs/"
cp "$ROOT/build/configs/db.template.yaml" "$DIST/configs/"
cp "$EDGE_NODE_ROOT/dist/edge-node-linux-amd64-community-v${NODE_VERSION}.zip" "$DIST/deploy/edge-node-linux-amd64-v${NODE_VERSION}.zip"

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -tags community -ldflags="-s -w" \
  -o "$DIST/installers/edge-installer-helper-linux-amd64" \
  "$ROOT/cmd/installer-helper/main.go"

GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
  go build -trimpath -tags community -ldflags="-s -w" \
  -o "$DIST/bin/edge-api" \
  "$ROOT/cmd/edge-api/main.go"

find "$DIST" -name ".DS_Store" -delete
find "$DIST" -name ".gitignore" -delete

(
  cd "$ROOT/dist"
  zip -r -X -q "edge-api-linux-amd64-community-v${VERSION}.zip" edge-api/
  sha256sum "edge-api-linux-amd64-community-v${VERSION}.zip" > SHA256SUMS.txt
)
