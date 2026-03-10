<h1>
  <img src='image.png' width="150" align="left">
  ADUC for Linux
</h1>

Python implementation of Microsoft's Active Directory Users and Computers for Linux.

## About

Migrating away from Windows while still working in a Microsoft environment has presented a few challenges, and the absense of good tools for managing Active Directory drove me to work on my own. Without naming other solutions out there, I have tried several, and they all... well... suck! This is a very basic tool for now, and I will try to add features as I can, but this very first version does at least what I need for now. 


## Sample Desktop Application Launcher

`~/.local/share/applications/aduc_for_linux.desktop`
```
Name=ADUC for Linux
Exec=/path/to/aduc_for_linux.py
Icon=/path/to/app_icon.png
Type=Application
Terminal=false
Categories=Utility;
```
