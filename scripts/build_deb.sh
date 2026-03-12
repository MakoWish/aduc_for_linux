#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '\n\r' < "${ROOT_DIR}/VERSION")"
PKG_NAME="aduc-for-linux"
BUILD_ROOT="${ROOT_DIR}/packaging/build"
STAGING_DIR="${BUILD_ROOT}/${PKG_NAME}_${VERSION}"
DEBIAN_DIR="${STAGING_DIR}/DEBIAN"
OUTPUT_DIR="${ROOT_DIR}/dist"

rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}" "${BUILD_ROOT}" "${OUTPUT_DIR}"
cp -a "${ROOT_DIR}/packaging/debian/." "${STAGING_DIR}/"

mkdir -p "${STAGING_DIR}/opt/aduc_for_linux"

install -m 0755 "${ROOT_DIR}/aduc_for_linux.py" "${STAGING_DIR}/opt/aduc_for_linux/aduc_for_linux.py"
install -m 0644 "${ROOT_DIR}/requirements.txt" "${STAGING_DIR}/opt/aduc_for_linux/requirements.txt"
install -m 0644 "${ROOT_DIR}/app_icon.png" "${STAGING_DIR}/opt/aduc_for_linux/app_icon.png"
install -m 0644 "${ROOT_DIR}/VERSION" "${STAGING_DIR}/opt/aduc_for_linux/VERSION"

sed -i "s/__VERSION__/${VERSION}/" "${DEBIAN_DIR}/control"

chmod 0755 "${DEBIAN_DIR}/postinst" "${DEBIAN_DIR}/prerm" "${STAGING_DIR}/usr/bin/aduc-for-linux"
find "${STAGING_DIR}" -type d -exec chmod 0755 {} +

dpkg-deb --build "${STAGING_DIR}" "${OUTPUT_DIR}/${PKG_NAME}_${VERSION}_all.deb"

echo "Built package: ${OUTPUT_DIR}/${PKG_NAME}_${VERSION}_all.deb"
