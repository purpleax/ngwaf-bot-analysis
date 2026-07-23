#!/usr/bin/env bash
# Build a self-contained macOS binary of the NGWAF dashboard using Node's
# Single Executable Applications (SEA) feature. Produces build/ngwaf-dashboard,
# which runs on a Mac WITHOUT Node installed. The Fastly token is NOT baked in —
# the binary reads a .env sitting next to it (or FASTLY_* env vars) at runtime.
#
# Usage:  npm run build:mac      (needs network the first time for esbuild/postject)
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="ngwaf-dashboard"
mkdir -p build

echo "1/5  bundling server + deps into one CJS file (esbuild)…"
VERSION="$(node -p "require('./package.json').version")"
STAMP="v${VERSION} built $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "     stamp: $STAMP"
npx --yes esbuild server.js --bundle --platform=node --format=cjs \
  --target=node18 --log-override:empty-import-meta=silent \
  --define:__BUILD_STAMP__="\"$STAMP\"" --outfile=build/app.cjs

echo "2/5  generating the SEA blob (embeds public/ assets)…"
node --experimental-sea-config sea-config.json

echo "3/5  fetching the official Node runtime (self-contained, has the SEA fuse)…"
# Homebrew/managed node is often a *shared* build (links libnode.dylib) with no
# SEA fuse, so injection fails. Use the official nodejs.org release binary instead.
NODE_VER="$(node -v)"                 # e.g. v26.3.0
case "$(uname -m)" in
  arm64)  NARCH="arm64" ;;
  x86_64) NARCH="x64" ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac
DIST="node-${NODE_VER}-darwin-${NARCH}"
RUNTIME="build/${DIST}/bin/node"
if [ ! -f "$RUNTIME" ]; then
  curl -fsSL "https://nodejs.org/dist/${NODE_VER}/${DIST}.tar.gz" -o "build/${DIST}.tar.gz"
  tar -xzf "build/${DIST}.tar.gz" -C build
fi
cp "$RUNTIME" "build/$NAME"
chmod u+w "build/$NAME"   # node ships mode 555; postject needs write access

# The postject sentinel fuse varies by node build, so read it from the binary.
FUSE="$(grep -a -o 'NODE_SEA_FUSE_[0-9a-f]*' "$RUNTIME" | sort -u | head -1)"
[ -n "$FUSE" ] || { echo "could not find SEA fuse sentinel in $RUNTIME"; exit 1; }
echo "     fuse: $FUSE"

echo "4/5  clearing the copied binary's signature…"
codesign --remove-signature "build/$NAME" || true

echo "5/5  injecting the blob and re-signing…"
npx --yes postject "build/$NAME" NODE_SEA_BLOB build/sea-prep.blob \
  --sentinel-fuse "$FUSE" \
  --macho-segment-name NODE_SEA
codesign --sign - "build/$NAME"

echo ""
echo "✓ Built build/$NAME  ($(du -h "build/$NAME" | cut -f1))"
echo "  Put a .env (with FASTLY_API_TOKEN + FASTLY_DEFAULT_CUSTOMER_ID) beside it, then run:"
echo "      ./build/$NAME"
echo "  → http://localhost:4000"
