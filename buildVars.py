from site_scons.site_tools.NVDATool.typings import AddonInfo, BrailleTables, SymbolDictionaries, SpeechDictionaries
from site_scons.site_tools.NVDATool.utils import _

addon_info = AddonInfo(
	addon_name="TwoFactorAuthenticator",
	addon_summary=_("2Factor Authenticator"),
	addon_description=_("Generates 2FA TOTP codes quickly via a shortcut key and copies them to the clipboard."),
<<<<<<< HEAD
	addon_version="1.5",
	addon_changelog=_("Added automatic QR code scanning from screen using opencv or wechat model to more compatibility with windows11 and nvda2026.2. no download needed, all libs are bundled. if you doubt libs are corrupted and not working? try: nvda menu > tools menu > 2fa menu and choose reinstall QRLibrary. the addon automatically reinstalls library and restarts nvda to continue."),
=======
	addon_version="1.5.2",
	addon_changelog=_("Added automatic QR code scanning from screenusing opencv or wechat model to more compativility with windows11 and nvda2026.2. no download needed, all libs are bundled. if you dout libs are currupted and not working? try: nvda menu>tools menu> 2fa menu and choose reinstall QRLibrary. the addon automatic reinstall Library and restart nvda to continue."),
>>>>>>> a9672c3719147edb533811710d61d52ae0cc7f6d
	addon_author="Umesh Rathore <umeshrathore897@gmail.com>",
	addon_url="https://github.com/umesh-rathore/2factor-authenticator",
	addon_sourceURL="https://github.com/umesh-rathore/2factor-authenticator",
	addon_docFileName="readme.html",
	addon_minimumNVDAVersion="2024.1",
	addon_lastTestedNVDAVersion="2026.2",
	addon_updateChannel=None,
)

pythonSources: list[str] = [
	"addon/globalPlugins/2factorAuthenticator/__init__.py",
]

i18nSources: list[str] = pythonSources + ["buildVars.py"]
excludedFiles: list[str] = []
baseLanguage: str = "en"
markdownExtensions: list[str] = []
brailleTables: BrailleTables = {}
symbolDictionaries: SymbolDictionaries = {}
speechDictionaries: SpeechDictionaries = {}