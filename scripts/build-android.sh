#!/usr/bin/env bash
# Cross-compile libmc5offline.so for Android with the NDK CMake toolchain.
#
#   ANDROID_NDK=/path/to/ndk scripts/build-android.sh [abi ...]
#
# Default ABIs are arm64-v8a and armeabi-v7a (the two MC5 ships). minSdkVersion 24
# matches the game's manifest. Output: build-android/<abi>/libmc5offline.so, also
# collected under artifacts/lib/<abi>/.
set -euo pipefail

NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-}}"
if [[ -z "${NDK}" || ! -f "${NDK}/build/cmake/android.toolchain.cmake" ]]; then
  echo "Set ANDROID_NDK to an NDK with build/cmake/android.toolchain.cmake" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${ANDROID_API:-24}"
ABIS=("$@")
if [[ ${#ABIS[@]} -eq 0 ]]; then ABIS=(arm64-v8a armeabi-v7a); fi

for abi in "${ABIS[@]}"; do
  out="${ROOT}/build-android/${abi}"
  cmake -S "${ROOT}" -B "${out}" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="${NDK}/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="${abi}" \
    -DANDROID_PLATFORM="android-${API}" \
    -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build "${out}"
  mkdir -p "${ROOT}/artifacts/lib/${abi}"
  cp "${out}/libmc5offline.so" "${ROOT}/artifacts/lib/${abi}/libmc5offline.so"
  size=$(stat -c%s "${ROOT}/artifacts/lib/${abi}/libmc5offline.so")
  echo "built ${abi}: libmc5offline.so (${size} bytes)"
done
