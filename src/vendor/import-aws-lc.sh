#!/bin/sh
# Re-extract the vendored AWS-LC subset from an official release tarball.
#
#   src/vendor/import-aws-lc.sh aws-lc-5.11.0.tar.gz
#
# Copies exactly the files listed in aws-lc.files into aws-lc/, unmodified.
# The tarball is checked against the sha256 below; to move to another
# release, change both lines, run this, rebuild, and add any file the build
# then reports missing to aws-lc.files.
set -eu

VERSION=5.11.0
SHA256=8cb24c6e6be1fa7ff05075c4560ca8b537a7ef48f9e6f465af4ea455794d74f4

TARBALL=${1:?usage: $0 aws-lc-$VERSION.tar.gz}
HERE=$(cd "$(dirname "$0")" && pwd)

echo "$SHA256  $TARBALL" | sha256sum -c -

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
tar -xzf "$TARBALL" -C "$TMP"
SRC=$TMP/aws-lc-$VERSION

rm -rf "$HERE/aws-lc"
while read -r f; do
    mkdir -p "$HERE/aws-lc/$(dirname "$f")"
    cp "$SRC/$f" "$HERE/aws-lc/$f"
done < "$HERE/aws-lc.files"
echo "imported $(wc -l < "$HERE/aws-lc.files") files from AWS-LC $VERSION"
