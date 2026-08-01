# 2Factor Authenticator - NVDA Global Plugin
# Generates TOTP (Time-based One-Time Password) codes for saved 2FA
# accounts and copies them to the clipboard.
#
# Default gesture: NVDA+Control+2

import os
import time
import hmac
import hashlib
import base64
import struct

import wx
import gui
import ui
import api
import globalVars
import addonHandler
import globalPluginHandler
from scriptHandler import script
from logHandler import log
from configobj import ConfigObj

addonHandler.initTranslation()

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


class AddAccountDialog(wx.Dialog):
	def __init__(self, parent):
		# Translators: title of the dialog to add a new 2FA account.
		super().__init__(parent, title=_("Add New 2FA Account"))
		sizer = wx.BoxSizer(wx.VERTICAL)

		# Translators: label of the account name field in the add account dialog.
		nameLabel = wx.StaticText(self, label=_("Account &name (e.g., GitHub):"))
		sizer.Add(nameLabel, 0, wx.LEFT | wx.RIGHT | wx.TOP, 5)
		self.nameCtrl = wx.TextCtrl(self)
		sizer.Add(self.nameCtrl, 0, wx.ALL | wx.EXPAND, 5)

		# Translators: label of the secret key field in the add account dialog.
		keyLabel = wx.StaticText(self, label=_("&Secret key:"))
		sizer.Add(keyLabel, 0, wx.LEFT | wx.RIGHT, 5)
		self.keyCtrl = wx.TextCtrl(self, style=wx.TE_PASSWORD)
		sizer.Add(self.keyCtrl, 0, wx.ALL | wx.EXPAND, 5)

		btnSizer = self.CreateButtonSizer(wx.OK | wx.CANCEL)
		sizer.Add(btnSizer, 0, wx.ALIGN_CENTER | wx.ALL, 10)

		self.SetSizer(sizer)
		sizer.Fit(self)
		self.nameCtrl.SetFocus()


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
		dlg = AddAccountDialog(self)
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
