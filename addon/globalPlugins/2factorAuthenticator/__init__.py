# 2Factor Authenticator - NVDA Global Plugin
# Generates TOTP (Time-based One-Time Password) codes for saved 2FA
# accounts and copies them to the clipboard.
#
# Default gesture: NVDA+Control+2

import os
import sys
import time
import hmac
import hashlib
import base64
import struct
import threading
import json
import zipfile
import tempfile
import shutil
import urllib.parse
import urllib.request

import wx
import gui
import ui
import api
import core
import queueHandler
import globalVars
import addonHandler
import globalPluginHandler
from scriptHandler import script
from logHandler import log
from configobj import ConfigObj

addonHandler.initTranslation()

# Automatic QR scanning needs two third-party libraries (Pillow, for taking
# a screenshot, and pyzbar, for reading the QR code out of it) that NVDA
# does NOT ship by default. They live in a "lib" folder next to this file.
# If that folder is missing or incomplete, offerQrDependencyDownload() below
# fetches the correct files for the user's actual NVDA (Windows 64-bit)
# Python version straight from PyPI - no manual pip step required.
_ADDON_DIR = os.path.dirname(os.path.abspath(__file__))
_LIB_DIR = os.path.join(_ADDON_DIR, "lib")
if os.path.isdir(_LIB_DIR) and _LIB_DIR not in sys.path:
	sys.path.insert(0, _LIB_DIR)


def _ensureDllSearchPaths():
	"""Since Python 3.8, Windows no longer implicitly searches for DLLs
	sitting next to the module that imports them - packages with bundled
	native DLLs (like pyzbar's libzbar-64.dll/libiconv.dll) need their
	folder registered explicitly with os.add_dll_directory(), or loading
	fails silently. Without this, QR_SCAN_AVAILABLE can end up False even
	though the files were downloaded and extracted correctly."""
	if not hasattr(os, "add_dll_directory"):
		return
	for candidate in (_LIB_DIR, os.path.join(_LIB_DIR, "pyzbar")):
		try:
			if os.path.isdir(candidate):
				os.add_dll_directory(candidate)
		except Exception:
			pass


def _importQrLibs():
	global ImageGrab, _zbarDecode
	_ensureDllSearchPaths()
	from PIL import ImageGrab
	from pyzbar.pyzbar import decode as _zbarDecode


QR_IMPORT_ERROR = None
try:
	_importQrLibs()
	QR_SCAN_AVAILABLE = True
except Exception as e:
	QR_SCAN_AVAILABLE = False
	QR_IMPORT_ERROR = str(e)
	log.error("2FA Manager: QR libraries not available: {}".format(e))


class _DownloadCancelled(Exception):
	pass


def _pickWheelUrl(files, pyTag):
	"""files: PyPI file list for one release. pyTag: e.g. 'cp311'.
	Returns the best-matching Windows 64-bit wheel URL, or None.
	"""
	wheels = [f for f in files if f.get("packagetype") == "bdist_wheel" and f.get("filename", "").endswith(".whl")]
	winWheels = [f for f in wheels if "win_amd64" in f.get("filename", "")]
	if not winWheels:
		return None
	for f in winWheels:
		if pyTag in f["filename"]:
			return f["url"]
	for f in winWheels:
		name = f["filename"]
		if "none-win_amd64" in name or "-none-any" in name or "py3-none" in name:
			return f["url"]
	# No exact interpreter match and no universal ("none"-tagged) wheel
	# either - every remaining option is compiled for a different Python
	# ABI and would just fail to import, so report "not found" instead of
	# silently downloading something that's guaranteed to be broken.
	return None


def _fetchPyPiWheelUrl(pkgName):
	"""Returns (wheelUrl, version) for the latest Windows 64-bit wheel of
	pkgName, or (None, None) if nothing suitable was found."""
	url = "https://pypi.org/pypi/{}/json".format(pkgName)
	req = urllib.request.Request(url, headers={"User-Agent": "TwoFactorAuthenticator-NVDA-Addon"})
	with urllib.request.urlopen(req, timeout=15) as resp:
		data = json.loads(resp.read().decode("utf-8"))
	version = data.get("info", {}).get("version")
	files = data.get("urls") or data.get("releases", {}).get(version, [])
	pyTag = "cp{}{}".format(sys.version_info.major, sys.version_info.minor)
	return _pickWheelUrl(files, pyTag), version


def _downloadFile(url, destPath, dlg, pkgName, idx, total):
	req = urllib.request.Request(url, headers={"User-Agent": "TwoFactorAuthenticator-NVDA-Addon"})
	with urllib.request.urlopen(req, timeout=20) as resp:
		totalSize = resp.getheader("Content-Length")
		totalSize = int(totalSize) if totalSize else 0
		downloaded = 0
		with open(destPath, "wb") as f:
			while True:
				if dlg.cancelled:
					raise _DownloadCancelled()
				chunk = resp.read(65536)
				if not chunk:
					break
				f.write(chunk)
				downloaded += len(chunk)
				if totalSize > 0:
					pctWithin = downloaded * 100 // totalSize
					overall = int((idx * 100 + pctWithin) / total)
					# Translators: {pkg} is a library name, {pct} a percentage.
					dlg.update(overall, _("Downloading {pkg}... {pct}%").format(pkg=pkgName, pct=pctWithin))
				else:
					dlg.update(-1, _("Downloading {pkg}...").format(pkg=pkgName))


def _downloadWorker(dlg):
	tmpDir = tempfile.mkdtemp(prefix="tfa_qr_deps_")
	try:
		packages = ["Pillow", "pyzbar"]
		for i, pkg in enumerate(packages):
			if dlg.cancelled:
				raise _DownloadCancelled()
			dlg.update(-1, _("Looking up {pkg}...").format(pkg=pkg))
			wheelUrl, version = _fetchPyPiWheelUrl(pkg)
			if not wheelUrl:
				raise RuntimeError(_("Could not find a compatible download for {pkg}.").format(pkg=pkg))
			wheelPath = os.path.join(tmpDir, pkg + ".whl")
			_downloadFile(wheelUrl, wheelPath, dlg, pkg, i, len(packages))
			if dlg.cancelled:
				raise _DownloadCancelled()
			with zipfile.ZipFile(wheelPath) as zf:
				zf.extractall(tmpDir)
		# Only touch the real lib folder once EVERYTHING above has fully
		# succeeded, so a cancel or a failed download never leaves a
		# half-installed, broken lib folder behind.
		os.makedirs(_LIB_DIR, exist_ok=True)
		for entry in os.listdir(tmpDir):
			if entry.endswith(".whl") or entry.endswith(".dist-info"):
				continue
			src = os.path.join(tmpDir, entry)
			dst = os.path.join(_LIB_DIR, entry)
			if os.path.isdir(dst):
				shutil.rmtree(dst, ignore_errors=True)
			elif os.path.isfile(dst):
				try: os.remove(dst)
				except Exception: pass
			shutil.move(src, dst)
		wx.CallAfter(_downloadFinished, dlg, True, None)
	except _DownloadCancelled:
		wx.CallAfter(_downloadFinished, dlg, False, None)
	except Exception as e:
		log.error("2FA Manager: QR dependency download failed", exc_info=True)
		wx.CallAfter(_downloadFinished, dlg, False, str(e))
	finally:
		shutil.rmtree(tmpDir, ignore_errors=True)


def _downloadFinished(dlg, success, error):
	try:
		if dlg.IsModal(): dlg.EndModal(wx.ID_OK)
	except Exception:
		pass
	try:
		dlg.Destroy()
	except Exception:
		pass
	if not success:
		if error:
			wx.MessageBox(_("Could not download the QR scanning files:\n{err}").format(err=error),
				_("Download Failed"), wx.OK | wx.ICON_ERROR)
		else:
			ui.message(_("Download cancelled."))
		return
	# Translators: shown after the QR scanning files finish downloading. {path} is the folder they were saved to.
	if wx.MessageBox(
		_("Download complete (saved to {path}). NVDA needs to restart for QR scanning to become available. Restart now?").format(path=_LIB_DIR),
		_("Restart Required"), wx.YES_NO | wx.ICON_INFORMATION | wx.YES_DEFAULT) == wx.YES:
		queueHandler.queueFunction(queueHandler.eventQueue, core.restart)
	else:
		ui.message(_("QR scanning will be available after you next restart NVDA."))


class DependencyDownloadDialog(wx.Dialog):
	def __init__(self, parent):
		# Translators: title of the download-progress dialog for QR scanning files.
		super().__init__(parent, title=_("Downloading QR Scanning Files"))
		self.cancelled = False
		sizer = wx.BoxSizer(wx.VERTICAL)
		self.msgLabel = wx.StaticText(self, label=_("Starting download..."))
		sizer.Add(self.msgLabel, 0, wx.ALL | wx.EXPAND, 10)
		self.gauge = wx.Gauge(self, range=100, size=(300, 20))
		sizer.Add(self.gauge, 0, wx.ALL | wx.EXPAND, 10)
		self.cancelBtn = wx.Button(self, wx.ID_CANCEL, label=_("Cancel"))
		self.cancelBtn.Bind(wx.EVT_BUTTON, self.onCancel)
		sizer.Add(self.cancelBtn, 0, wx.ALIGN_CENTER | wx.ALL, 10)
		self.Bind(wx.EVT_CLOSE, self.onCancel)
		self.SetSizerAndFit(sizer)
		self.CenterOnParent()

	def onCancel(self, event):
		self.cancelled = True
		try: self.cancelBtn.Disable()
		except Exception: pass
		try:
			if self.IsModal(): self.EndModal(wx.ID_CANCEL)
			else: self.Close()
		except Exception:
			pass

	def update(self, pct, msg):
		if wx.IsMainThread():
			self._doUpdate(pct, msg)
		else:
			wx.CallAfter(self._doUpdate, pct, msg)

	def _doUpdate(self, pct, msg):
		try:
			if self.IsBeingDeleted(): return
			if pct < 0: self.gauge.Pulse()
			else: self.gauge.SetValue(max(0, min(100, pct)))
			self.msgLabel.SetLabel(msg)
		except Exception:
			pass


def offerQrDependencyDownload(parentWindow, isStartupCheck=False):
	"""Checks for the QR scanning libraries and, if missing, offers to
	download them. Safe to call both from the automatic startup check and
	from the user explicitly choosing "Automatic" in Add Account.
	isStartupCheck=True remembers a "no" answer so NVDA startup doesn't
	nag about it again every time - the user can still get the download
	prompt any time via Add Account > Automatic.
	"""
	if QR_SCAN_AVAILABLE:
		return True
	filesAlreadyPresent = os.path.isdir(_LIB_DIR) and bool(os.listdir(_LIB_DIR))
	if filesAlreadyPresent:
		# The files are there but failed to load - re-downloading them
		# would look identical to the user and teach them nothing, so show
		# exactly where they are and why loading failed instead.
		wx.MessageBox(
			_("QR scanning files were found in:\n{path}\n\nbut failed to load:\n{err}\n\n"
				"Try deleting that \"lib\" folder and downloading again, or check the NVDA "
				"log (NVDA menu > Tools > View Log) for the full error.").format(
				path=_LIB_DIR, err=QR_IMPORT_ERROR or _("unknown error")),
			_("QR Scanning Unavailable"), wx.OK | wx.ICON_ERROR)
		return False
	ans = wx.MessageBox(
		_("Automatic QR code scanning needs a one-time download of about 15 MB. Download it now?"),
		_("Download Required"), wx.YES_NO | wx.ICON_QUESTION)
	if ans != wx.YES:
		if isStartupCheck:
			_saveQrPromptDeclined()
		return False
	dlg = DependencyDownloadDialog(parentWindow)
	threading.Thread(target=_downloadWorker, args=(dlg,), daemon=True).start()
	gui.mainFrame.prePopup()
	try:
		dlg.ShowModal()
	finally:
		gui.mainFrame.postPopup()
	return False

# IMPORTANT: the accounts database is stored inside NVDA's user configuration
# directory, NOT inside this add-on's own install folder.
# Storing it under the add-on folder (as os.path.dirname(__file__)) is a
# common mistake: that folder is deleted and recreated every time the add-on
# is updated or reinstalled, which would silently wipe out every saved
# account. It can also live under Program Files, which normal user accounts
# can't write to. globalVars.appArgs.configPath is the per-user NVDA config
# folder and is always writable and persists across add-on updates.
CONFIG_DIR = os.path.join(globalVars.appArgs.configPath, "twoFactorAuthenticator")
CONFIG_PATH = os.path.join(CONFIG_DIR, "accounts.ini")
# A separate small file from accounts.ini on purpose - preferences have no
# business living in the same file as saved account secrets.
SETTINGS_PATH = os.path.join(CONFIG_DIR, "settings.ini")


def _qrPromptWasDeclined():
	try:
		cfg = ConfigObj(SETTINGS_PATH, encoding="UTF-8")
		return cfg.as_bool("qrDownloadDeclined") if "qrDownloadDeclined" in cfg else False
	except Exception:
		return False


def _saveQrPromptDeclined():
	try:
		if not os.path.isdir(CONFIG_DIR):
			os.makedirs(CONFIG_DIR, exist_ok=True)
		cfg = ConfigObj(SETTINGS_PATH, encoding="UTF-8", create_empty=True)
		cfg["qrDownloadDeclined"] = True
		cfg.write()
	except Exception:
		log.error("2FA Manager: could not save settings", exc_info=True)


def _normalizeSecret(secret):
	"""Clean up a user supplied Base32 secret and pad it correctly."""
	secret = str(secret).replace(" ", "").strip().upper()
	secret = secret.rstrip("=")
	missingPadding = len(secret) % 8
	if missingPadding:
		secret += "=" * (8 - missingPadding)
	return secret


def isValidSecret(secret):
	"""Return True if secret can be decoded as a Base32 TOTP secret."""
	try:
		base64.b32decode(_normalizeSecret(secret), casefold=True)
		return True
	except Exception:
		return False


def getTotpCode(secret, digits=6, period=30):
	"""Generate the current TOTP code for the given Base32 secret.
	Returns None if the secret is invalid.
	"""
	try:
		key = base64.b32decode(_normalizeSecret(secret), casefold=True)
		intervalsNo = int(time.time() // period)
		msg = struct.pack(">Q", intervalsNo)
		hmacHash = hmac.new(key, msg, hashlib.sha1).digest()
		offset = hmacHash[-1] & 0x0F
		binaryCode = struct.unpack(">I", hmacHash[offset:offset + 4])[0] & 0x7FFFFFFF
		code = binaryCode % (10 ** digits)
		return str(code).zfill(digits)
	except Exception:
		log.error("2FA Manager: failed to generate OTP", exc_info=True)
		return None


def _parseOtpauthUri(uri):
	"""Pulls (label, secret) out of an otpauth://totp/... URI.
	Returns (None, None) if it isn't a usable otpauth URI.
	"""
	try:
		parsed = urllib.parse.urlparse(uri)
		if parsed.scheme.lower() != "otpauth":
			return None, None
		qs = urllib.parse.parse_qs(parsed.query)
		secret = (qs.get("secret") or [None])[0]
		if not secret:
			return None, None
		label = urllib.parse.unquote(parsed.path).lstrip("/").strip()
		issuer = (qs.get("issuer") or [None])[0]
		if issuer and issuer not in label:
			label = "{}: {}".format(issuer, label) if label else issuer
		# Translators: fallback account name used when a scanned QR code
		# doesn't include a usable label.
		return (label or _("Scanned Account")), secret
	except Exception:
		return None, None


def scanScreenForOtpSecret():
	"""Takes a screenshot and looks for an otpauth:// QR code anywhere on
	it. Returns (label, secret), or (None, None) if nothing was found or
	the QR libraries aren't available.
	"""
	if not QR_SCAN_AVAILABLE:
		return None, None
	try:
		img = ImageGrab.grab()
		for result in _zbarDecode(img):
			try:
				data = result.data.decode("utf-8", errors="ignore")
			except Exception:
				continue
			if data.lower().startswith("otpauth://"):
				return _parseOtpauthUri(data)
	except Exception:
		log.error("2FA Manager: screen QR scan failed", exc_info=True)
	return None, None


class AddAccountDialog(wx.Dialog):
	def __init__(self, parent, prefillName=None, prefillSecret=None):
		# Translators: title of the dialog to add a new 2FA account.
		super().__init__(parent, title=_("Add New 2FA Account"))
		sizer = wx.BoxSizer(wx.VERTICAL)

		# Translators: label of the account name field in the add account dialog.
		nameLabel = wx.StaticText(self, label=_("Account &name (e.g., GitHub):"))
		sizer.Add(nameLabel, 0, wx.LEFT | wx.RIGHT | wx.TOP, 5)
		self.nameCtrl = wx.TextCtrl(self)
		if prefillName:
			self.nameCtrl.SetValue(prefillName)
		sizer.Add(self.nameCtrl, 0, wx.ALL | wx.EXPAND, 5)

		# Translators: label of the secret key field in the add account dialog.
		keyLabel = wx.StaticText(self, label=_("&Secret key:"))
		sizer.Add(keyLabel, 0, wx.LEFT | wx.RIGHT, 5)
		self.keyCtrl = wx.TextCtrl(self, style=wx.TE_PASSWORD)
		if prefillSecret:
			self.keyCtrl.SetValue(prefillSecret)
		sizer.Add(self.keyCtrl, 0, wx.ALL | wx.EXPAND, 5)

		btnSizer = self.CreateButtonSizer(wx.OK | wx.CANCEL)
		sizer.Add(btnSizer, 0, wx.ALIGN_CENTER | wx.ALL, 10)

		self.SetSizer(sizer)
		sizer.Fit(self)
		self.nameCtrl.SetFocus()


# IDs returned by AddAccountModeDialog.ShowModal(); chosen well clear of any
# stock wx IDs so they can never collide with wx.ID_OK/CANCEL/etc.
ID_MODE_AUTO = 9001
ID_MODE_MANUAL = 9002


class AddAccountModeDialog(wx.Dialog):
	def __init__(self, parent):
		# Translators: title of the add-account mode choice dialog.
		super().__init__(parent, title=_("Add New 2FA Account"))
		sizer = wx.BoxSizer(wx.VERTICAL)

		# Translators: instruction shown above the Automatic/Manual choice.
		hint = wx.StaticText(self, label=_("How would you like to add this account?"))
		sizer.Add(hint, 0, wx.ALL, 10)

		autoLabel = _("&Automatic - scan a QR code from screen") if QR_SCAN_AVAILABLE \
			else _("&Automatic - scan a QR code from screen (one-time download needed)")
		self.autoBtn = wx.Button(self, label=autoLabel)
		self.autoBtn.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(ID_MODE_AUTO))
		sizer.Add(self.autoBtn, 0, wx.ALL | wx.EXPAND, 5)

		# Translators: manual entry option in the add-account mode choice dialog.
		self.manualBtn = wx.Button(self, label=_("&Manual - type the account name and secret key"))
		self.manualBtn.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(ID_MODE_MANUAL))
		sizer.Add(self.manualBtn, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM | wx.EXPAND, 5)

		cancelBtnSizer = self.CreateButtonSizer(wx.CANCEL)
		sizer.Add(cancelBtnSizer, 0, wx.ALIGN_CENTER | wx.ALL, 10)

		self.SetSizerAndFit(sizer)
		self.CenterOnParent()
		self.autoBtn.SetFocus()


class Master2FAManager(wx.Dialog):
	def __init__(self, parent, plugin):
		# Translators: title of the 2FA accounts manager dialog.
		super().__init__(parent, title=_("2Factor Authenticator Manager"))
		self.plugin = plugin

		mainSizer = wx.BoxSizer(wx.VERTICAL)
		# Translators: label above the list of saved 2FA accounts.
		listLabel = wx.StaticText(self, label=_("Saved accounts:"))
		mainSizer.Add(listLabel, 0, wx.LEFT | wx.RIGHT | wx.TOP, 5)

		self.accountsList = wx.ListBox(self, style=wx.LB_SINGLE)
		mainSizer.Add(self.accountsList, 1, wx.ALL | wx.EXPAND, 5)

		btnRowSizer = wx.BoxSizer(wx.HORIZONTAL)

		# Translators: button to add a 2FA account.
		self.addBtn = wx.Button(self, label=_("&Add Account"))
		self.addBtn.Bind(wx.EVT_BUTTON, self.onAddAccount)
		btnRowSizer.Add(self.addBtn, 0, wx.ALL, 5)

		# Translators: button to delete a 2FA account.
		self.deleteBtn = wx.Button(self, label=_("&Delete Account"))
		self.deleteBtn.Bind(wx.EVT_BUTTON, self.onDeleteAccount)
		btnRowSizer.Add(self.deleteBtn, 0, wx.ALL, 5)

		# Translators: button to copy the current OTP code to the clipboard.
		self.copyBtn = wx.Button(self, label=_("&Copy OTP Code"))
		self.copyBtn.Bind(wx.EVT_BUTTON, self.onCopyOtp)
		btnRowSizer.Add(self.copyBtn, 0, wx.ALL, 5)

		mainSizer.Add(btnRowSizer, 0, wx.ALIGN_CENTER, 5)

		closeBtnSizer = self.CreateButtonSizer(wx.CLOSE)
		mainSizer.Add(closeBtnSizer, 0, wx.ALIGN_RIGHT | wx.ALL, 10)

		self.SetSizer(mainSizer)
		self.refreshList()
		self.SetMinSize((400, 300))
		mainSizer.Fit(self)

	def refreshList(self):
		self.accountsList.Clear()
		self.plugin.config.reload()
		for account in sorted(self.plugin.config.keys()):
			self.accountsList.Append(account)
		if self.accountsList.GetCount() > 0:
			self.accountsList.SetSelection(0)

	def onAddAccount(self, event):
		modeDlg = AddAccountModeDialog(self)
		gui.mainFrame.prePopup()
		try:
			choice = modeDlg.ShowModal()
		finally:
			modeDlg.Destroy()
			gui.mainFrame.postPopup()

		if choice == ID_MODE_MANUAL:
			self._openAddDialog(None, None)
		elif choice == ID_MODE_AUTO:
			if not QR_SCAN_AVAILABLE:
				offerQrDependencyDownload(self)
				return
			self._runAutoScan()
		# else: cancelled, nothing to do

	def _runAutoScan(self):
		self._scanTimedOut = False
		# Safety net: if the background scan ever hangs (e.g. a broken
		# native library), tell the user instead of leaving them waiting
		# forever with no feedback.
		self._scanTimeoutTimer = wx.CallLater(15000, self._onScanTimeout)
		# IMPORTANT: this dialog is currently shown with ShowModal(), and
		# hiding a dialog while it's still modal is unreliable on Windows -
		# it can leave the modal loop in a broken state with nothing
		# visibly happening. So instead of hiding it, ask the user to
		# switch to their QR code window themselves, then wait a few
		# seconds before scanning - our dialog just ends up behind theirs
		# once they switch, with no Hide()/Show() needed at all.
		ui.message(_("Switch to the window showing your QR code now. Scanning in 3 seconds..."))
		wx.CallLater(3000, self._startScanThread)

	def _startScanThread(self):
		if getattr(self, "_scanTimedOut", False):
			return
		threading.Thread(target=self._autoScanWorker, daemon=True).start()

	def _autoScanWorker(self):
		label, secret = scanScreenForOtpSecret()
		wx.CallAfter(self._autoScanDone, label, secret)

	def _onScanTimeout(self):
		self._scanTimedOut = True
		try:
			if self.IsBeingDeleted(): return
		except Exception:
			log.error("2FA Manager: IsBeingDeleted check failed in scan timeout", exc_info=True)
			return
		try: self.Raise()
		except Exception: pass
		wx.MessageBox(
			_("The QR scan is taking too long and may have failed. Please try again, or use Manual entry instead."),
			_("Scan Timed Out"), wx.OK | wx.ICON_WARNING)

	def _autoScanDone(self, label, secret):
		try:
			timer = getattr(self, "_scanTimeoutTimer", None)
			if timer: timer.Stop()
		except Exception:
			pass
		if getattr(self, "_scanTimedOut", False):
			# Already told the user it timed out; a late result now would
			# just be confusing, so quietly ignore it.
			return
		try:
			if self.IsBeingDeleted(): return
		except Exception:
			log.error("2FA Manager: IsBeingDeleted check failed after scan", exc_info=True)
			return
		try: self.Raise()
		except Exception: pass
		if not secret:
			if wx.MessageBox(
				_("No QR code found on screen. Make sure it's fully visible, then try again?"),
				_("Not Found"), wx.YES_NO | wx.ICON_WARNING) == wx.YES:
				self._runAutoScan()
			return
		self._openAddDialog(label, secret)

	def _openAddDialog(self, prefillName, prefillSecret):
		dlg = AddAccountDialog(self, prefillName, prefillSecret)
		try:
			gui.mainFrame.prePopup()
			result = dlg.ShowModal()
			gui.mainFrame.postPopup()
			if result != wx.ID_OK:
				return

			name = dlg.nameCtrl.GetValue().strip()
			secret = dlg.keyCtrl.GetValue().strip()

			if not name or not secret:
				# Translators: error shown when name or secret is missing.
				wx.MessageBox(_("Both a name and a secret key are required."),
					_("Error"), wx.OK | wx.ICON_ERROR)
				return

			if not isValidSecret(secret):
				# Translators: error shown when the entered secret key isn't valid Base32.
				wx.MessageBox(
					_("That secret key doesn't look valid. Please check it and try again."),
					_("Error"), wx.OK | wx.ICON_ERROR)
				return

			if name in self.plugin.config:
				# Translators: confirmation shown when overwriting an existing account.
				if wx.MessageBox(
					_("An account named {name} already exists. Replace it?").format(name=name),
					_("Confirm"), wx.YES_NO | wx.ICON_QUESTION) != wx.YES:
					return

			self.plugin.config[name] = secret
			self.plugin.config.write()
			self.refreshList()
			# Translators: message reported after an account is saved.
			ui.message(_("{name} account saved.").format(name=name))
		finally:
			dlg.Destroy()

	def onDeleteAccount(self, event):
		selection = self.accountsList.GetStringSelection()
		if not selection:
			# Translators: message when no account is selected for deletion.
			ui.message(_("No account selected."))
			return

		# Translators: confirmation shown before deleting an account.
		if wx.MessageBox(_("Are you sure you want to delete {name}?").format(name=selection),
				_("Confirm Delete"), wx.YES_NO | wx.ICON_QUESTION) == wx.YES:
			del self.plugin.config[selection]
			self.plugin.config.write()
			self.refreshList()
			# Translators: message reported after an account is deleted.
			ui.message(_("{name} deleted.").format(name=selection))

	def onCopyOtp(self, event):
		selection = self.accountsList.GetStringSelection()
		if not selection:
			ui.message(_("No account selected."))
			return
		self.plugin.copyOtp(selection)


class GlobalPlugin(globalPluginHandler.GlobalPlugin):
	# Translators: category shown for this add-on's commands in the
	# NVDA Input Gestures dialog.
	scriptCategory = _("2FA Manager")

	def __init__(self):
		super().__init__()

		if not os.path.isdir(CONFIG_DIR):
			os.makedirs(CONFIG_DIR, exist_ok=True)

		self.config = ConfigObj(CONFIG_PATH, encoding="UTF-8", create_empty=True)

		# Translators: label of the 2FA Manager item added to the NVDA Tools menu.
		self.menuItem = gui.mainFrame.sysTrayIcon.toolsMenu.Append(
			wx.ID_ANY, _("2FA Manager...")
		)
		gui.mainFrame.sysTrayIcon.Bind(wx.EVT_MENU, self.onManagerMenuItem, self.menuItem)

		# Give NVDA's GUI time to finish starting up before possibly
		# popping a dialog.
		try: wx.CallLater(4000, self._startupDependencyCheck)
		except Exception: pass

	def _startupDependencyCheck(self):
		if QR_SCAN_AVAILABLE or _qrPromptWasDeclined():
			return
		try:
			offerQrDependencyDownload(gui.mainFrame, isStartupCheck=True)
		except Exception:
			log.error("2FA Manager: startup dependency check failed", exc_info=True)

	def onManagerMenuItem(self, evt):
		wx.CallAfter(self.showManagerGui)

	def showManagerGui(self):
		dlg = Master2FAManager(gui.mainFrame, self)
		gui.mainFrame.prePopup()
		try:
			dlg.ShowModal()
		finally:
			dlg.Destroy()
			gui.mainFrame.postPopup()

	@script(
		# Translators: description of the OTP command shown in the
		# NVDA Input Gestures dialog.
		description=_("Generates the OTP code for a saved 2FA account and copies it to the clipboard"),
		gesture="kb:NVDA+control+2",
	)
	def script_generateOTP(self, gesture):
		self.config.reload()
		accounts = list(self.config.keys())

		if not accounts:
			ui.message(_("No 2FA accounts found. Open 2FA Manager to add one."))
			return

		if len(accounts) == 1:
			self.copyOtp(accounts[0])
			return

		wx.CallAfter(self.showSelectionGui, accounts)

	def showSelectionGui(self, accounts):
		gui.mainFrame.prePopup()
		dlg = wx.SingleChoiceDialog(
			gui.mainFrame, _("Select account for OTP:"), _("2Factor Authenticator"), accounts
		)
		try:
			if dlg.ShowModal() == wx.ID_OK:
				self.copyOtp(dlg.GetStringSelection())
		finally:
			dlg.Destroy()
			gui.mainFrame.postPopup()

	def copyOtp(self, accountName):
		secret = self.config.get(accountName)
		if not secret:
			ui.message(_("Secret not found."))
			return

		otp = getTotpCode(secret)
		if not otp:
			ui.message(_("Invalid secret key format."))
			return

		if api.copyToClip(otp):
			# Translators: reports the copied OTP code, {name} is the account
			# name and {code} is the 6 digit one-time password.
			ui.message(_("OTP for {name} copied: {code}").format(name=accountName, code=otp))
		else:
			ui.message(_("Clipboard error."))

	def terminate(self):
		try:
			gui.mainFrame.sysTrayIcon.toolsMenu.Remove(self.menuItem)
		except Exception:
			log.debug("2FA Manager: menu item already removed", exc_info=True)
