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
