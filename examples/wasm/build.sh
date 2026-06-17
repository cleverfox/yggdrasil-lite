#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building WASM..."
wasm-pack build --target web --out-dir www/pkg

echo ""
echo "Build complete.  Serve with:"
echo "  cd www && python3 -m http.server 8080"
echo "  then open http://localhost:8080"
