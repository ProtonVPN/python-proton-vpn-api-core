#!/usr/bin/env bash

# This is a temporary script to download the python3-proton-core and python3-proton-vpn-local-agent
# packages required to create the python3-proton-vpn-api-core package. It's currently needed when we
# the package is created on our arm64 gitlab runner, because it doesn't have access to our dev linux repos.
# We plan to get rid of the -proton-core and -local-agent dependencies soon, or to get an arm64 gitlab
# runner that has access to our dev linux repos.


set -euo pipefail

ARCH="$1"

. /etc/os-release

OUTPUT_DIR="target/dependencies/$ID/$VERSION_ID/$ARCH"
mkdir -p "$OUTPUT_DIR"

download_debian() {
    local pkg="$1"
    local target_arch="$2"
    local native_arch
    native_arch="$(dpkg --print-architecture)"

    ORIG_URL=$(apt-get download --print-uris "$pkg:$native_arch" | cut -d' ' -f1 | sed "s/'\(.*\)'/\1/g")
    URL=$(echo "$ORIG_URL" | sed "s/${native_arch}/${target_arch}/g")
    echo "Original url ${ORIG_URL}"
    echo "Downloading  ${URL}"
    wget "$URL" -P "$OUTPUT_DIR"
}

download_fedora() {
    local pkg="$1"
    local target_arch="$2"

    echo "Downloading ${pkg} on ${target_arch}"
    dnf download --destdir "$OUTPUT_DIR" --arch "$target_arch" "$pkg"
}

download_package() {
    local pkg="$1"
    local target_arch="$2"

    case "$ID" in
        debian) download_debian "$pkg" "$target_arch" ;;
        fedora) download_fedora "$pkg" "$target_arch" ;;
        *)      echo "Unsupported distro: $ID" >&2; exit 1 ;;
    esac
}

# Explicit package declarations with their arch requirements
download_package python3-proton-core noarch
