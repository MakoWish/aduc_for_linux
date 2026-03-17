# ADUC for Linux

Python implementation of Microsoft's **Active Directory Users and Computers (ADUC)** for Linux desktops. Manage Microsoft and Samba AD from Linux!

<img src="image.png" width="150" alt="ADUC for Linux icon">

## Index

* [About](#about)  
* [Features](#features-current)  
* [Requirements](#requirements)  
* [Installation](#installation)  
* [Running Manually](#running-manually-without-launcher)  
* [Configuration](#configuration)  
* [Roadmap](#roadmap-ideas)  
* [Donate](#donate)
* [Contributing](#contributing)  
* [Disclaimer](#disclaimer)

## About

Migrating away from Windows while still managing Microsoft environments can be painful. This project aims to provide a lightweight ADUC-style GUI that works natively on Linux and covers practical day-to-day LDAP/AD object browsing and administration needs.

It is intentionally small and focused: one Python app, one installer script, and minimal runtime dependencies. Additional features will continue to be added. If there is something you would like to see added, please open an Issue and request it!

**_NOTE_**: Also works against **_Samba Active Directory_** domain controllers!

## Features (current)

- Browse Active Directory hierarchy (domains, containers, OUs).
- Work with common object types:
  - Users
  - Groups
  - Computers
  - Organizational Units
- Create users, groups, computers, and organizational units from Action/context menus.
- Basic ADUC-like iconography and object-state overlays.
- Support Kerberos authentication.
- Savable connection profiles with secure password storage in system keyring.
- Simple `.deb` package installation.
- Desktop launcher installation for ease of of opening from Application Launcher.
- Startup version check against GitHub with update prompt when a newer release is available.

## Requirements

- Linux desktop environment with GUI support.
  - Currently only packaging `.deb` for Debian/Ubuntu flavors.
- Python 3 (with `venv` support).
- One of:
  - `wget` or
  - `curl`
- Network access from your Linux machine to your Active Directory domain controllers.

Python dependencies are listed in `requirements.txt` and installed into a virtual environment by the installer.

## Installation

### Debian package (recommended)

Download the latest `.deb` from [GitHub Releases](https://github.com/MakoWish/aduc_for_linux/releases/latest), then install it:

```bash
sudo apt install ./aduc-for-linux_<version>_all.deb
```

Using `apt install ./package.deb` is recommended, because it automatically resolves required system dependencies.
If you use `dpkg -i` directly and see dependency errors, run:

```bash
sudo apt -f install
```

After install, launch from your Application Launcher menu, or run:

```bash
aduc-for-linux
```

### Quick Install

```bash
bash <(wget -qO- https://raw.githubusercontent.com/MakoWish/aduc_for_linux/main/install.sh)
```

If running as root, you will be prompted to install for all users or just for yourself. If not running as root, installation is user-local.

The installer will:

1. Download required app files.
2. Create a virtual environment.
3. Install Python dependencies.
4. Create a `.desktop` launcher entry.
5. Install a local `VERSION` file used by the app startup update check.

### Build from Source

If you would like to build this project directly from source, download the latest archive:

- [Source code (zip)](https://github.com/MakoWish/aduc_for_linux/archive/refs/tags/latest.zip)
- [Source code (tar.gz)](https://github.com/MakoWish/aduc_for_linux/archive/refs/tags/latest.tar.gz)

... and compile:

```bash
make check
make build-deb
```

The compiled `.deb` package will be placed in `./dist/aduc-for-linux_<version>_all.deb`.

#### Running Manually (without launcher)

```bash
python3 aduc_for_linux.py
```

For normal use, prefer running through the installed virtual environment (launcher does this automatically).

## Configuration

On initial launch, you will need to first connect to a domain controller via **_File > Connect_**. If you are working from a domain-joined machine, you may optionally enable `Kerberos / SSO` for the connection's authentication mechanism. Otherwise, select `Credentials` to authenticate using explicity login credentials.

Multiple profiles may be created for different account/connection, as well as optionally store credentials securely to your system's keyring. When using stored credentials or `Kerberos / SSO` authentication, you may optionally choose to auto-connect on application launch. These preferences are stored to your local profile in:

- `~/.config/aduc-linux/settings.json`

### Kerberos note for Samba AD

Some Samba AD environments enforce LDAP strong-auth requirements that mandate SASL GSSAPI sign/seal. Depending on the `ldap3`/Kerberos stack available in the app runtime, Kerberos bind may fail in those environments even while it works against Microsoft AD.

If that happens, switch to **Credentials** authentication mode in ADUC for Linux; simple bind over LDAPS will still work in typical Samba AD setups.

## Roadmap Ideas

Potential next improvements:

- Expand object management actions and dialogs.
- Add automated tests beyond syntax validation.
- Expand packaging options (AppImage/Flatpak/RPM).

## Donate

Like this project? [Buy me a coffee!](buymeacoffee.com/MakoWish) 

## Contributing

Want to contribute to this project? Please feel free to open an [Issue](https://github.com/MakoWish/aduc_for_linux/issues) with your suggestions, and we can collaborate on PR's.

## Disclaimer

This is an independent project and is not an official Microsoft product. Although all efforts are made to ensure this project works without issue, use at your own risk.
