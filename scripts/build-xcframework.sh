#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds target/KhensuCore.xcframework (iOS, iOS Simulator, macOS on arm64)
# and the Swift bindings in target/swift/.
set -euo pipefail

cd "$(dirname "$0")/.."
root=$(pwd)
targets=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
lib=libkhensu_ffi.a
out=$root/target/KhensuCore.xcframework
swift=$root/target/swift
stage=$root/target/xcframework-stage

export IPHONEOS_DEPLOYMENT_TARGET=26.0
export MACOSX_DEPLOYMENT_TARGET=26.0

rustup target add "${targets[@]}" >/dev/null 2>&1
for t in "${targets[@]}"; do
    cargo build -p khensu-ffi --release --target "$t"
done

cargo run -q -p khensu-uniffi-bindgen --bin uniffi-bindgen -- \
    generate --library target/aarch64-apple-darwin/release/libkhensu_ffi.dylib --language swift --out-dir "$swift"

rm -rf "$stage" "$out"
mkdir -p "$stage/headers"
cp "$swift/KhensuCoreFFI.h" "$stage/headers/"
cp "$swift/KhensuCoreFFI.modulemap" "$stage/headers/module.modulemap"

args=()
for t in "${targets[@]}"; do
    args+=(-library "target/$t/release/$lib" -headers "$stage/headers")
done
xcodebuild -create-xcframework "${args[@]}" -output "$out" >/dev/null
rm -rf "$stage"

echo "$out"
echo "$swift/KhensuCore.swift"
