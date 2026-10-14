#!/usr/bin/env bash
# Builds the site into ./dist (the folder GitHub Pages serves).
# One-time setup:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version 0.2.100 --locked
set -euo pipefail

cargo build --release --target wasm32-unknown-unknown

rm -rf dist
mkdir -p dist
wasm-bindgen --target web --no-typescript --out-dir dist/pkg \
  target/wasm32-unknown-unknown/release/steg_studio.wasm
cp -r www/* dist/

echo "Built ./dist — preview with: python3 -m http.server -d dist 8080"
