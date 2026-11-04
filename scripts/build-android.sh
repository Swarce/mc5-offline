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

# Vendored TLS dependency: mbedTLS, pinned + verified. Fetched on first build so
# the ~5 MB source isn't committed. The release tarball is self-contained
# (bundles the framework + generated sources).
MBEDTLS_VER="3.6.2"
MBEDTLS_SHA256="8b54fb9bcf4d5a7078028e0520acddefb7900b3e66fec7f7175bb5b7d85ccdca"
MBEDTLS_DIR="${ROOT}/third_party/mbedtls"
if [[ ! -f "${MBEDTLS_DIR}/CMakeLists.txt" ]]; then
  echo "fetching mbedTLS ${MBEDTLS_VER}..."
  mkdir -p "${ROOT}/third_party"
  tb="${ROOT}/third_party/mbedtls-${MBEDTLS_VER}.tar.bz2"
  url="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VER}/mbedtls-${MBEDTLS_VER}.tar.bz2"
  curl -fsSL -o "${tb}" "${url}"
  got=$(sha256sum "${tb}" | cut -d' ' -f1)
  if [[ "${got}" != "${MBEDTLS_SHA256}" ]]; then
    echo "mbedTLS checksum mismatch: got ${got}, expected ${MBEDTLS_SHA256}" >&2
    rm -f "${tb}"; exit 1
  fi
  tar -xjf "${tb}" -C "${ROOT}/third_party"
  mv "${ROOT}/third_party/mbedtls-${MBEDTLS_VER}" "${MBEDTLS_DIR}"
  rm -f "${tb}"
  echo "mbedTLS ${MBEDTLS_VER} ready at third_party/mbedtls"
fi

# Loopback TLS cert+key for the embedded listener. Self-signed, verify-none (the
# client never checks it), loopback-only — not a secret, but a private key, so it
# is generated per machine and never committed.
CERT_HDR="${ROOT}/hosts/embedded/tls_cert.hpp"
if [[ ! -f "${CERT_HDR}" ]]; then
  echo "generating loopback TLS cert..."
  tmpd="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -keyout "${tmpd}/key.pem" -out "${tmpd}/cert.pem" \
    -days 36500 -nodes -subj "/CN=mc5offline" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:eve.gameloft.com,DNS:*.gameloft.com,DNS:*.ecomapis.com" >/dev/null 2>&1
  {
    echo "// Generated loopback TLS cert+key (self-signed, verify-none). Regenerated"
    echo "// per machine by build-android.sh; never committed."
    echo "#pragma once"
    echo "namespace mc5 {"
    echo "inline const char kTlsCertPem[] ="
    printf 'R"MC5PEM(%s)MC5PEM";\n' "$(cat "${tmpd}/cert.pem")"
    echo "inline const char kTlsKeyPem[] ="
    printf 'R"MC5PEM(%s)MC5PEM";\n' "$(cat "${tmpd}/key.pem")"
    echo "} // namespace mc5"
  } > "${CERT_HDR}"
  rm -rf "${tmpd}"
  echo "wrote hosts/embedded/tls_cert.hpp"
fi

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
