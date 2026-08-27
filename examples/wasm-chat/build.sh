#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building WASM (reusing ../wasm crate)..."
# This example ships no Rust crate of its own — it reuses the yggdrasil_wasm crate
# from ../wasm and only adds a different web front-end.
wasm-pack build ../wasm --target web --out-dir "$(pwd)/www/pkg"

echo ""
echo "Build complete.  Serve with:"
echo "  cd www && python3 -m http.server 8081"
echo "  then open http://localhost:8081"
