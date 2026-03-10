# ADUC for Linux

<img src="image.png" width="150">

Python implementation of Microsoft's Active Directory Users and Computers for Linux.

## About

Migrating away from Windows while still working in a Microsoft environment has presented a few challenges, and the absense of good tools for managing Active Directory drove me to work on my own. Without naming other solutions out there, I have tried several, and they all... well... suck! This is a very basic tool for now, and I will try to add features as I can, but this very first version does at least what I need for now. 

## Installation

### Quick install

```bash
bash <(wget -qO- https://raw.githubusercontent.com/MakoWish/aduc_for_linux/main/install.sh)
```

If running as root, you will be prompted to install for all users, or just for yourself. If not running as root, the install will be for your profile only.

A `.desktop` file will be generated for you (or all users) so the application may be opened from Application Launcher.
