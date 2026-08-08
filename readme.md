# 2FactorAuthenticator

This package contains the 2FactorAuthenticator NVDA add-on. It allows you to save your 2FA secret keys and quickly generate TOTP codes using a shortcut key.

## Features

* **Easy Management:** Add and manage your 2FA accounts directly from the NVDA Tools menu.
* **Fast OTP Generation:** Press `NVDA+Ctrl+2` to instantly copy your TOTP code to the clipboard.
* **Standalone:** Runs completely offline and requires no external system-wide dependencies.
##note:
* code fast copy and paste because sum sights like github no long time. you can generated code pasted in 30 seconds.
## How to Build

1. Clone the repository to your computer.
2. Open your command line and navigate to the project folder.
3. Type the following command and press Enter:
   ```cmd
   scons
   ## Changelog

**1.5**
* Added automatic QR code scanning from screen (requires Pillow and pyzbar libraries, downloaded automatically on first use)

**1.4**
* Improved error handling and logging for easier troubleshooting
* Minor stability fixes

**1.3**
* Fixed an issue where adding an account with a name that already existed would silently overwrite it without warning
* Added validation for secret keys when adding an account

**1.2**
* Fixed clipboard copy reliability on some systems
* General bug fixes

**1.1**
* Fixed saved accounts being lost after updating the add-on (accounts are now stored in NVDA's user configuration folder instead of the add-on's install folder)
* Minor bug fixes

**1.0**
* Initial release
