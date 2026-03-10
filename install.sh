#!/usr/bin/env bash
set -euo pipefail

APP_NAME="ADUC for Linux"
APP_ID="aduc-for-linux"
REPO_RAW_BASE="https://raw.githubusercontent.com/MakoWish/aduc_for_linux/main"

PY_FILE="aduc_for_linux.py"
ICON_FILE="app_icon.png"
REQ_FILE="requirements.txt"
VERSION_FILE="VERSION"

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

prompt_yes_no() {
    local prompt="$1"
    local reply
    while true; do
        read -r -p "$prompt [y/n]: " reply
        case "${reply,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
        esac
    done
}

download_file() {
    local url="$1"
    local out="$2"

    if have_cmd wget; then
        wget -qO "$out" "$url"
    elif have_cmd curl; then
        curl -fsSL "$url" -o "$out"
    else
        echo "Error: neither wget nor curl is installed."
        exit 1
    fi
}

require_cmd() {
    local cmd="$1"
    if ! have_cmd "$cmd"; then
        echo "Error: required command not found: $cmd"
        exit 1
    fi
}

choose_mode() {
    if [[ "$EUID" -eq 0 ]]; then
        echo "Running as root."
        echo "1) Install for all users"
        echo "2) Install just for me"
        while true; do
            read -r -p "Choose 1 or 2: " choice
            case "$choice" in
                1) INSTALL_MODE="system"; return ;;
                2) INSTALL_MODE="user"; return ;;
            esac
        done
    else
        echo "Not running as root."
        if prompt_yes_no "Install just for me? If you want to install for all users, re-launch with sudo."; then
            INSTALL_MODE="user"
        else
            echo "Aborted."
            exit 0
        fi
    fi
}

resolve_paths() {
    local real_user real_home xdg_data_home

    if [[ "$INSTALL_MODE" == "system" ]]; then
        INSTALL_DIR="/opt/aduc_for_linux"
        DESKTOP_DIR="/usr/share/applications"
        DESKTOP_FILE="${DESKTOP_DIR}/${APP_ID}.desktop"
        return
    fi

    if [[ "$EUID" -eq 0 ]]; then
        real_user="${SUDO_USER:-}"
        if [[ -z "$real_user" ]]; then
            echo "Error: cannot determine target user for per-user install while running as root."
            exit 1
        fi
        real_home="$(getent passwd "$real_user" | cut -d: -f6)"
    else
        real_user="$USER"
        real_home="$HOME"
    fi

    if [[ -z "$real_home" ]]; then
        echo "Error: cannot determine target home directory."
        exit 1
    fi

    xdg_data_home="${XDG_DATA_HOME:-${real_home}/.local/share}"

    INSTALL_OWNER="$real_user"
    INSTALL_GROUP="$(id -gn "$real_user")"
    INSTALL_DIR="${real_home}/.local/opt/aduc_for_linux"
    DESKTOP_DIR="${xdg_data_home}/applications"
    DESKTOP_FILE="${DESKTOP_DIR}/${APP_ID}.desktop"
}

fetch_files() {
    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DESKTOP_DIR"

    echo "Downloading files..."
    download_file "${REPO_RAW_BASE}/${PY_FILE}"   "${tmpdir}/${PY_FILE}"
    download_file "${REPO_RAW_BASE}/${ICON_FILE}" "${tmpdir}/${ICON_FILE}"
    download_file "${REPO_RAW_BASE}/${REQ_FILE}"  "${tmpdir}/${REQ_FILE}"
    download_file "${REPO_RAW_BASE}/${VERSION_FILE}" "${tmpdir}/${VERSION_FILE}"

    install -m 0755 "${tmpdir}/${PY_FILE}"   "${INSTALL_DIR}/${PY_FILE}"
    install -m 0644 "${tmpdir}/${ICON_FILE}" "${INSTALL_DIR}/${ICON_FILE}"
    install -m 0644 "${tmpdir}/${REQ_FILE}"  "${INSTALL_DIR}/${REQ_FILE}"
    install -m 0644 "${tmpdir}/${VERSION_FILE}" "${INSTALL_DIR}/${VERSION_FILE}"
}

setup_venv() {
    require_cmd python3
    require_cmd install

    echo "Creating virtual environment..."
    python3 -m venv "${INSTALL_DIR}/venv"

    echo "Installing dependencies..."
    "${INSTALL_DIR}/venv/bin/python" -m pip install --upgrade pip
    "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/${REQ_FILE}"
}

write_desktop_file() {
    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=${APP_NAME}
Comment=Active Directory Users and Computers for Linux
Exec=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/${PY_FILE}
Icon=${INSTALL_DIR}/${ICON_FILE}
Terminal=false
Categories=System;Utility;
StartupNotify=true
EOF

    chmod 0644 "$DESKTOP_FILE"
}

fix_ownership() {
    if [[ "$INSTALL_MODE" == "user" ]]; then
        chown -R "${INSTALL_OWNER}:${INSTALL_GROUP}" "$INSTALL_DIR" "$DESKTOP_DIR"
    fi
}

main() {
    choose_mode
    resolve_paths
    fetch_files
    setup_venv
    write_desktop_file
    fix_ownership

    echo
    echo "Installed successfully."
    echo "Application directory: $INSTALL_DIR"
    echo "Desktop entry: $DESKTOP_FILE"
}

main "$@"
