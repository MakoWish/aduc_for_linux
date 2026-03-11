# ADUC for Linux

Python implementation of Microsoft's **Active Directory Users and Computers (ADUC)** for Linux desktops.

<img src="image.png" width="150" alt="ADUC for Linux icon">

## Index

[About](#about)  
[Features](#features-current)

## About

Migrating away from Windows while still managing Microsoft environments can be painful. This project aims to provide a lightweight ADUC-style GUI that works natively on Linux and covers practical day-to-day LDAP/AD object browsing and administration needs.

It is intentionally small and focused: one Python app, one installer script, and minimal runtime dependencies.

## Features (current)

- Browse Active Directory hierarchy (domains, containers, OUs).
- Work with common object types:
  - Users
  - Groups
  - Computers
  - Organizational Units
- Create users, groups, computers, and organizational units from Action/context menus.
- Basic ADUC-like iconography and object-state overlays.
- Desktop launcher installation for user-only or system-wide installs.
- Startup version check against GitHub with update prompt when a newer release is available.

## Requirements

- Linux desktop environment with GUI support.
- Python 3 (with `venv` support).
- One of:
  - `wget` or
  - `curl`
- Network access from your Linux machine to your Active Directory domain controllers.

Python dependencies are listed in `requirements.txt` and installed into a virtual environment by the installer.

## Installation

### Quick install

```bash
bash <(wget -qO- https://raw.githubusercontent.com/MakoWish/aduc_for_linux/main/install.sh)
```

If running as root, you will be prompted to install for all users or just for yourself. If not running as root, installation is user-local.

The installer will:

1. Download the app files.
2. Create a virtual environment.
3. Install Python dependencies.
4. Create a `.desktop` launcher entry.
5. Install a local `VERSION` file used by the app startup update check.

## Running manually (without launcher)

```bash
python3 aduc_for_linux.py
```

For normal use, prefer running through the installed virtual environment (launcher does this automatically).

## Configuration

The app stores some preference settings in:

- `~/.config/aduc-linux/settings.json`

## Project checks

This repository now includes a minimal `Makefile` with a `check` target.

Run all checks:

```bash
make check
```

Included checks:

- Python syntax validation:
  - `python3 -m py_compile aduc_for_linux.py`
- Installer shell syntax validation:
  - `bash -n install.sh`

These checks are intentionally dependency-light, so contributors can quickly validate basic repo health before committing.

## Development notes

- Main application entry point: `aduc_for_linux.py`
- Installer: `install.sh`
- Dependencies: `requirements.txt`

## Roadmap ideas

Potential next improvements:

- Expand object management actions and dialogs.
- Add configurable connection profiles.
- Add automated tests beyond syntax validation.
- Improve packaging options (native packages/AppImage/Flatpak).

## Disclaimer

This is an independent project and is not an official Microsoft product. Although all efforts are made to ensure this project works without issue, use at your own risk.

## Donate

Like this project? [Buy me a coffee!](buymeacoffee.com/MakoWish) 
