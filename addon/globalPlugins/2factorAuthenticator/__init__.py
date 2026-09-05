# 2Factor Authenticator - NVDA Global Plugin
# Generates TOTP (Time-based One-Time Password) codes for saved 2FA
# accounts and copies them to the clipboard.
#
# Default gesture: NVDA+Control+2 - copies the code for the (only, or
# selected) saved account directly.
#
# Full account management (add/delete/import/export/scan) is available
# from: NVDA menu > Tools > 2FA > Manage Accounts...
#
# QR scanning is fully OPTIONAL and NOT bundled with this addon. It uses
# OpenCV's built-in QRCodeDetector (not pyzbar), because pyzbar needs the
# external zbar shared library (libzbar-64.dll on Windows), which itself
# requires the Visual C++ Redistributable - a common source of "does not
# work on Windows 11" failures.
#
# The required libraries (opencv-contrib-python-headless, numpy, pillow) are
# downloaded directly from PyPI (fetching the .whl and extracting it with
# zipfile - no pip required, since NVDA's embedded Python does not ship
# pip) into a "qrlib" folder next to this file. NVDA offers this download
# once on startup; declining is remembered permanently, and it can always
# be retried later from Tools > 2FA > Reinstall QR Library.

import os
import sys
import time
import hmac
import hashlib
import base64
import struct
import json
import shutil
import threading
import zipfile
import tempfile
import urllib.parse
import urllib.request

import wx
import gui
import ui
import api
import core
import globalVars
import addonHandler
import globalPluginHandler
from scriptHandler import script
from logHandler import log
from configobj import ConfigObj

addonHandler.initTranslation()

# ---------------------------------------------------------------------------
# Optional QR-scanning support. Nothing here runs or imports anything heavy
# at addon start-up - QR_SUPPORT just reflects whether the libraries are
# already present from a previous download.
# ---------------------------------------------------------------------------
QR_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qrlib")
if os.path.isdir(QR_LIB_DIR) and QR_LIB_DIR not in sys.path:
    sys.path.insert(0, QR_LIB_DIR)

# Every screen-scan attempt overwrites this file with exactly what was
# captured, whether or not a QR code was found in it. This is the single
# most useful diagnostic when a scan reports "not found" but the code
# looks visible on screen to the user - it separates "capture is fine
# but decoding failed" from "capture itself is wrong/blank/stale".
DEBUG_SCREENSHOT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "last_scan_debug.png"
)

cv2 = None
np = None
ImageGrab = None
QR_SUPPORT = False
WECHAT_QR_SUPPORT = False
_wechatDetector = None

QR_PACKAGES = ("opencv-contrib-python-headless", "numpy", "pillow")

# The classical cv2.QRCodeDetector struggles with exactly the case this
# addon hits constantly: a QR code that's small and low-contrast relative
# to a full, busy desktop screenshot. WeChat's DNN-based detector (shipped
# in opencv-contrib, not the plain opencv-python package) is dramatically
# more reliable for that specific scenario, but needs four small model
# files (~1MB total) that aren't bundled in the wheel and have to be
# fetched separately from their upstream host.
WECHAT_MODEL_BASE_URL = "https://raw.githubusercontent.com/WeChatCV/opencv_3rdparty/wechat_qrcode/"
WECHAT_MODEL_FILES = ("detect.prototxt", "detect.caffemodel", "sr.prototxt", "sr.caffemodel")
WECHAT_MODEL_DIR = os.path.join(QR_LIB_DIR, "wechat_models")


class _CancelledError(Exception):
    pass


def tryImportQrLibs():
    """Attempts to import the optional QR libraries and initialize the
    WeChat QR detector. Never raises - returns True/False for the base
    QR_SUPPORT flag. Safe to call repeatedly (e.g. after a download)."""
    global cv2, np, ImageGrab, QR_SUPPORT, WECHAT_QR_SUPPORT, _wechatDetector
    try:
        import numpy as _np
        import cv2 as _cv2
        from PIL import ImageGrab as _ImageGrab
        np = _np
        cv2 = _cv2
        ImageGrab = _ImageGrab
        QR_SUPPORT = True
    except Exception as e:
        log.debug("2FA Manager: QR libraries not available yet: {}".format(e))
        QR_SUPPORT = False

    WECHAT_QR_SUPPORT = False
    _wechatDetector = None
    if QR_SUPPORT and hasattr(cv2, "wechat_qrcode_WeChatQRCode"):
        modelPaths = [os.path.join(WECHAT_MODEL_DIR, f) for f in WECHAT_MODEL_FILES]
        if all(os.path.isfile(p) for p in modelPaths):
            try:
                _wechatDetector = cv2.wechat_qrcode_WeChatQRCode(*modelPaths)
                WECHAT_QR_SUPPORT = True
            except Exception as e:
                log.debug("2FA Manager: WeChat QR detector init failed: {}".format(e))

    return QR_SUPPORT


tryImportQrLibs()


def _isWheelCompatible(filename, pyMajor, pyMinor):
    """Returns True if the wheel filename is genuinely safe to load into
    this exact running CPython (pyMajor, pyMinor) on 64-bit Windows.

    Understands the two tagging schemes actually used by these packages:
    - Version-specific compiled wheels, e.g. numpy's
      "numpy-2.5.2-cp313-cp313-win_amd64.whl" - must match this Python
      exactly.
    - CPython stable-ABI ("abi3") wheels, e.g. opencv-contrib-python-headless's
      single "opencv_contrib_python_headless-5.0.0.93-cp37-abi3-win_amd64.whl"
      - built against the Limited API, and by CPython's own ABI
      guarantee this is forward-compatible with every newer 3.x release,
      not just the exact one named in the tag.
    A pure "py3-none-any" wheel (no compiled code at all) is always safe
    too, though none of our three packages currently ship one.

    Anything else is rejected: guessing at a near-enough tag risks
    pulling in a binary built against a different CPython ABI, and
    mixing that with correctly-matched files in the same qrlib folder is
    exactly the kind of thing that produces an unrecoverable native
    "Visual C++ Runtime Library" crash instead of a catchable Python
    exception."""
    if not filename.endswith(".whl"):
        return False
    stem = filename[:-4]
    parts = stem.split("-")
    if len(parts) < 3:
        return False
    platform_tag, abi_tag, python_tag = parts[-1], parts[-2], parts[-3]

    if abi_tag == "none" and python_tag.startswith("py"):
        return platform_tag == "any" or "win_amd64" in platform_tag

    if "win_amd64" not in platform_tag:
        return False
    if not python_tag.startswith("cp") or len(python_tag) < 3:
        return False
    verDigits = python_tag[2:]
    if not verDigits.isdigit():
        return False
    tagMajor = int(verDigits[0])
    tagMinor = int(verDigits[1:]) if len(verDigits) > 1 else 0

    if abi_tag == "abi3":
        # Stable-ABI wheel: forward-compatible with this and any newer
        # CPython 3.x release, per CPython's own ABI guarantee.
        return tagMajor == pyMajor and tagMinor <= pyMinor

    # Version-specific compiled wheel: must match this Python exactly.
    return abi_tag == python_tag and tagMajor == pyMajor and tagMinor == pyMinor


def _findWheelUrl(pkgName):
    """Looks up the latest release of pkgName on PyPI and returns the
    download URL of a .whl file that is safe to use with this exact
    running CPython on 64-bit Windows. Returns None if nothing suitable
    is found."""
    with urllib.request.urlopen(
        "https://pypi.org/pypi/{}/json".format(pkgName), timeout=30
    ) as resp:
        meta = json.loads(resp.read().decode("utf-8"))

    for entry in meta.get("urls", []):
        if _isWheelCompatible(
            entry.get("filename", ""), sys.version_info.major, sys.version_info.minor
        ):
            return entry["url"]
    return None



def _downloadWithProgress(url, destPath, onBytes):
    """Downloads url to destPath, calling onBytes(downloaded, total) as
    data arrives. total may be 0 if the server didn't send a length.
    onBytes may raise _CancelledError to abort the download."""
    req = urllib.request.Request(url, headers={"User-Agent": "NVDA-2FA-Addon"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        with open(destPath, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                onBytes(downloaded, total)


def downloadQrLibsAsync(onProgress, onDone, cancelEvent):
    """Downloads opencv-contrib-python-headless, numpy, pillow, and the
    WeChat QR detector's small model files, in a background thread.

    Downloads are extracted into a temporary staging folder first; the
    real QR_LIB_DIR is only replaced once everything has extracted
    successfully. This means a cancelled or failed download never
    leaves a previously-working install broken.

    onProgress(percent, message) and onDone(success, errorMessage) are
    both called on the wx main thread. cancelEvent is a threading.Event;
    setting it aborts the download as soon as possible."""

    def worker():
        success = False
        error = None
        stagingDir = QR_LIB_DIR + "_staging"
        try:
            if os.path.isdir(stagingDir):
                shutil.rmtree(stagingDir, ignore_errors=True)
            os.makedirs(stagingDir, exist_ok=True)
            # The WeChat model download counts as one extra "package" for
            # progress-percentage purposes.
            total_steps = len(QR_PACKAGES) + 1

            for i, pkgName in enumerate(QR_PACKAGES):
                if cancelEvent.is_set():
                    raise _CancelledError()

                wx.CallAfter(
                    onProgress, int(i / total_steps * 100),
                    _("Looking up {}...").format(pkgName),
                )
                url = _findWheelUrl(pkgName)
                if not url:
                    raise RuntimeError(
                        _("No compatible download found for {} (Python {}.{}, 64-bit Windows).").format(
                            pkgName, sys.version_info.major, sys.version_info.minor
                        )
                    )

                with tempfile.TemporaryDirectory() as tmpDir:
                    whlPath = os.path.join(tmpDir, pkgName + ".whl")

                    def onBytes(downloaded, total, i=i, pkgName=pkgName):
                        if cancelEvent.is_set():
                            raise _CancelledError()
                        if total:
                            pct = int((i + downloaded / total) / total_steps * 100)
                        else:
                            pct = int(i / total_steps * 100)
                        wx.CallAfter(onProgress, pct, _("Downloading {}...").format(pkgName))

                    _downloadWithProgress(url, whlPath, onBytes)

                    if cancelEvent.is_set():
                        raise _CancelledError()

                    wx.CallAfter(
                        onProgress, int((i + 1) / total_steps * 100),
                        _("Installing {}...").format(pkgName),
                    )
                    with zipfile.ZipFile(whlPath) as z:
                        z.extractall(stagingDir)

            # WeChat's DNN-based QR detector needs four small model files
            # that aren't bundled in the pip wheel. It's a large accuracy
            # upgrade over the classical detector for a QR code that's
            # small/low-contrast against a busy desktop screenshot, so
            # it's worth the ~1MB extra fetch - but its absence is never
            # fatal, since decodeQrFromImage() falls back to the classical
            # detector if these files aren't present.
            modelStageDir = os.path.join(stagingDir, "wechat_models")
            os.makedirs(modelStageDir, exist_ok=True)
            modelIdx = len(QR_PACKAGES)
            for j, fname in enumerate(WECHAT_MODEL_FILES):
                if cancelEvent.is_set():
                    raise _CancelledError()
                wx.CallAfter(
                    onProgress, int(modelIdx / total_steps * 100),
                    _("Downloading QR detector model ({}/{})...").format(j + 1, len(WECHAT_MODEL_FILES)),
                )
                destPath = os.path.join(modelStageDir, fname)

                def onModelBytes(downloaded, total):
                    if cancelEvent.is_set():
                        raise _CancelledError()

                try:
                    _downloadWithProgress(WECHAT_MODEL_BASE_URL + fname, destPath, onModelBytes)
                except _CancelledError:
                    raise
                except Exception as e:
                    # Non-fatal: the classical detector still works
                    # without these, so just log it and move on.
                    log.debug("2FA Manager: WeChat model download failed for {}: {}".format(fname, e))

            # Everything extracted cleanly - now swap it into place.
            # Mixing compiled extensions from two different Python ABI
            # builds in the same folder is a common cause of native
            # crashes that Python cannot catch or recover from, so the
            # old folder is fully removed rather than merged into.
            if os.path.isdir(QR_LIB_DIR):
                shutil.rmtree(QR_LIB_DIR, ignore_errors=True)
            shutil.move(stagingDir, QR_LIB_DIR)

            wx.CallAfter(onProgress, 100, _("Done."))
            success = True
        except _CancelledError:
            error = "Cancelled"
        except Exception as e:
            log.error("2FA Manager: QR download failed: {}".format(e))
            error = str(e)
        finally:
            shutil.rmtree(stagingDir, ignore_errors=True)
        wx.CallAfter(onDone, success, error)

    threading.Thread(target=worker, daemon=True).start()


def parseOtpauthUri(uri):
    """Parses an otpauth://totp/ URI and returns a dictionary with keys:
    'secret', 'issuer', 'label', 'digits', 'period', 'algorithm'.
    Returns None if parsing fails.
    """
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme != "otpauth" or parsed.netloc != "totp":
            return None

        label = urllib.parse.unquote(parsed.path.lstrip("/"))
        params = urllib.parse.parse_qs(parsed.query)

        secret = params.get("secret", [None])[0]
        if not secret:
            return None

        secret = secret.strip().replace(" ", "").upper()

        issuer = params.get("issuer", [None])[0]
        if not issuer and ":" in label:
            issuer, label = label.split(":", 1)
            issuer = issuer.strip()
            label = label.strip()

        digits = int(params.get("digits", [6])[0])
        period = int(params.get("period", [30])[0])
        algo = params.get("algorithm", ["SHA1"])[0].upper()

        return {
            "secret": secret,
            "issuer": issuer or _("Unknown Issuer"),
            "label": label or _("Unknown Account"),
            "digits": digits,
            "period": period,
            "algorithm": algo,
        }
    except Exception as e:
        log.error("2FA Manager: Failed to parse URI: {}".format(e))
        return None


def generateTotp(secret, digits=6, period=30, algorithm="SHA1"):
    """Generates a standard Time-based One-Time Password."""
    try:
        secret = secret.strip().replace(" ", "").upper()
        missing_padding = (-len(secret)) % 8
        if missing_padding:
            secret += "=" * missing_padding
        key = base64.b32decode(secret, casefold=True)
    except Exception as e:
        log.error("2FA Manager: Base32 decoding failed: {}".format(e))
        return None

    intervals = int(time.time() // period)
    msg = struct.pack(">Q", intervals)

    algo_lower = algorithm.lower()
    if not hasattr(hashlib, algo_lower):
        log.error("2FA Manager: Unsupported algorithm {}".format(algorithm))
        return None
    hash_module = getattr(hashlib, algo_lower)

    try:
        hmac_hash = hmac.new(key, msg, hash_module).digest()
    except Exception as e:
        log.error("2FA Manager: HMAC computing failed: {}".format(e))
        return None

    offset = hmac_hash[-1] & 0x0F
    code = (
        (hmac_hash[offset] & 0x7F) << 24
        | (hmac_hash[offset + 1] & 0xFF) << 16
        | (hmac_hash[offset + 2] & 0xFF) << 8
        | (hmac_hash[offset + 3] & 0xFF)
    )

    str_code = str(code % (10 ** digits))
    return str_code.zfill(digits)


def _qrTileCrops(gray, grid=3, overlap=0.2):
    """Yields overlapping crops of a grayscale image in a grid x grid
    layout. Splitting a full-screen capture into tiles and scanning each
    one lets the detector focus on a smaller region at a time, which
    matters far more for a QR code that's small relative to the whole
    screen than blindly upscaling the entire screenshot would (upscaling
    a screenshot that's already 1920x1080+ just interpolates existing
    pixels - it doesn't recover detail the capture never had)."""
    h, w = gray.shape[:2]
    step_h, step_w = h // grid, w // grid
    pad_h, pad_w = int(step_h * overlap), int(step_w * overlap)
    for row in range(grid):
        for col in range(grid):
            y0 = max(0, row * step_h - pad_h)
            x0 = max(0, col * step_w - pad_w)
            y1 = min(h, (row + 1) * step_h + pad_h)
            x1 = min(w, (col + 1) * step_w + pad_w)
            yield gray[y0:y1, x0:x1]


def _tryDecodeOn(detector, image):
    """Runs both the single- and multi-code detectors on one image and
    returns the first decoded text found, or None."""
    try:
        data, points, _straight = detector.detectAndDecode(image)
        if data:
            return data
    except cv2.error:
        pass
    try:
        ok, decoded, _points, _straight = detector.detectAndDecodeMulti(image)
        if ok:
            for d in decoded:
                if d:
                    return d
    except cv2.error:
        pass
    return None


def _tryWeChatDecode(image):
    """Runs the WeChat DNN-based QR detector (if its model files were
    downloaded) on a BGR image. Returns decoded text or None. Never
    raises."""
    if not WECHAT_QR_SUPPORT:
        return None
    try:
        results, points = _wechatDetector.detectAndDecode(image)
        for r in results:
            if r:
                return r
    except Exception as e:
        log.debug("2FA Manager: WeChat QR decode failed: {}".format(e))
    return None


def decodeQrFromImage(img):
    """Decodes a QR code from a numpy BGR image array using OpenCV.

    OpenCV's classical detector is noticeably less forgiving than
    dedicated QR libraries (like zbar) about screen-capture artifacts:
    anti-aliased edges, low contrast against a busy background, or a
    code that's small relative to the full screenshot. WeChat's
    DNN-based detector (opencv-contrib) handles exactly that case far
    more reliably, so it's tried first - on the whole frame, then
    tile-by-tile - before falling back to the classical detector's own
    whole-frame and tiled passes.

    Returns the decoded text, or None if nothing was found."""
    if not QR_SUPPORT:
        return None
    try:
        data = _tryWeChatDecode(img)
        if data:
            return data

        if WECHAT_QR_SUPPORT:
            grayForWeChatTiles = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            for tile in _qrTileCrops(grayForWeChatTiles, grid=3, overlap=0.2):
                th, tw = tile.shape[:2]
                if th < 20 or tw < 20:
                    continue
                data = _tryWeChatDecode(cv2.cvtColor(tile, cv2.COLOR_GRAY2BGR))
                if data:
                    return data

        detector = cv2.QRCodeDetector()
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # --- Fast path: try the whole frame a few different ways -----
        wholeFrameCandidates = [img, gray]
        try:
            wholeFrameCandidates.append(
                cv2.adaptiveThreshold(
                    gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                    cv2.THRESH_BINARY, 35, 5,
                )
            )
        except cv2.error:
            pass
        for candidate in wholeFrameCandidates:
            data = _tryDecodeOn(detector, candidate)
            if data:
                return data
        if hasattr(detector, "detectAndDecodeCurved"):
            try:
                data, points, _straight = detector.detectAndDecodeCurved(gray)
                if data:
                    return data
            except cv2.error:
                pass

        # --- Slower fallback: tile the screen and upscale each tile --
        for tile in _qrTileCrops(gray, grid=3, overlap=0.2):
            th, tw = tile.shape[:2]
            if th < 20 or tw < 20:
                continue
            upscaled = cv2.resize(tile, (tw * 2, th * 2), interpolation=cv2.INTER_CUBIC)
            data = _tryDecodeOn(detector, upscaled)
            if data:
                return data

        return None
    except Exception as e:
        log.error("2FA Manager: QR decode failed: {}".format(e))
        return None


def pilImageToCvMat(pilImage):
    """Converts a PIL Image (RGB) to an OpenCV BGR numpy array."""
    arr = np.array(pilImage.convert("RGB"))
    return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)


# ---------------------------------------------------------------------------
# Quick-copy dialog: shown by the NVDA+Control+2 gesture only when there is
# more than one saved account, so the user can pick which one to copy.
# ---------------------------------------------------------------------------
class QuickCopyDialog(wx.Dialog):
    def __init__(self, parent, plugin):
        super().__init__(parent, title=_("Copy 2FA Code"))
        self.plugin = plugin

        sizer = wx.BoxSizer(wx.VERTICAL)
        lbl = wx.StaticText(self, label=_("Select an &account:"))
        sizer.Add(lbl, 0, wx.ALL, 10)

        self.list = wx.ListBox(self, size=(320, 200), style=wx.LB_SINGLE)
        for name in plugin.getAccountNames():
            self.list.Append(name)
        if self.list.GetCount() > 0:
            self.list.SetSelection(0)
        self.list.Bind(wx.EVT_LISTBOX_DCLICK, self.onCopy)
        sizer.Add(self.list, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        btnSizer = wx.BoxSizer(wx.HORIZONTAL)
        copyBtn = wx.Button(self, label=_("&Copy Code"))
        copyBtn.Bind(wx.EVT_BUTTON, self.onCopy)
        btnSizer.Add(copyBtn, 0, wx.ALL, 5)
        cancelBtn = wx.Button(self, wx.ID_CANCEL, label=_("Cancel"))
        btnSizer.Add(cancelBtn, 0, wx.ALL, 5)
        sizer.Add(btnSizer, 0, wx.ALIGN_CENTER | wx.ALL, 10)

        self.SetSizerAndFit(sizer)
        self.CenterOnScreen()
        self.list.SetFocus()

    def onCopy(self, event):
        sel = self.list.GetSelection()
        if sel == wx.NOT_FOUND:
            return
        name = self.list.GetString(sel)
        self.plugin.copyCodeForAccount(name)
        self.EndModal(wx.ID_OK)


# ---------------------------------------------------------------------------
# Full account manager dialog: add/delete/import/export/scan/copy. Opened
# from NVDA menu > Tools > 2FA > Manage Accounts...
# ---------------------------------------------------------------------------
class AuthenticatorDialog(wx.Dialog):
    def __init__(self, parent, plugin):
        # Translators: Title of the 2FA account manager dialog.
        super().__init__(parent, title=_("2-Factor Authenticator"))
        self.plugin = plugin

        mainSizer = wx.BoxSizer(wx.VERTICAL)

        lbl = wx.StaticText(self, label=_("Saved &Accounts:"))
        mainSizer.Add(lbl, 0, wx.ALL, 10)

        self.accountsList = wx.ListBox(self, size=(380, 220), style=wx.LB_SINGLE)
        # Fixed: wx.EVT_LISTBOX_DBOX is not a real wx event and would raise
        # an AttributeError on addon load. The correct event for a
        # double-click on a wx.ListBox is wx.EVT_LISTBOX_DCLICK.
        self.accountsList.Bind(wx.EVT_LISTBOX_DCLICK, self.onCopyToken)
        mainSizer.Add(self.accountsList, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        btnSizer1 = wx.BoxSizer(wx.HORIZONTAL)
        self.btnCopy = wx.Button(self, label=_("&Copy Code"))
        self.btnCopy.Bind(wx.EVT_BUTTON, self.onCopyToken)
        btnSizer1.Add(self.btnCopy, 0, wx.ALL, 5)

        self.btnAdd = wx.Button(self, label=_("&Add Account..."))
        self.btnAdd.Bind(wx.EVT_BUTTON, self.onAddAccount)
        btnSizer1.Add(self.btnAdd, 0, wx.ALL, 5)

        self.btnDelete = wx.Button(self, label=_("&Delete"))
        self.btnDelete.Bind(wx.EVT_BUTTON, self.onDeleteAccount)
        btnSizer1.Add(self.btnDelete, 0, wx.ALL, 5)
        mainSizer.Add(btnSizer1, 0, wx.ALIGN_CENTER | wx.LEFT | wx.RIGHT | wx.TOP, 10)

        btnSizer2 = wx.BoxSizer(wx.HORIZONTAL)
        self.btnImport = wx.Button(self, label=_("&Import Backup..."))
        self.btnImport.Bind(wx.EVT_BUTTON, self.onImportBackup)
        btnSizer2.Add(self.btnImport, 0, wx.ALL, 5)

        self.btnExport = wx.Button(self, label=_("&Export Backup..."))
        self.btnExport.Bind(wx.EVT_BUTTON, self.onExportBackup)
        btnSizer2.Add(self.btnExport, 0, wx.ALL, 5)
        mainSizer.Add(btnSizer2, 0, wx.ALIGN_CENTER | wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)

        ccSizer = self.CreateButtonSizer(wx.CLOSE)
        if ccSizer:
            mainSizer.Add(ccSizer, 0, wx.ALIGN_RIGHT | wx.BOTTOM | wx.RIGHT, 10)

        self.SetSizerAndFit(mainSizer)
        self.CenterOnScreen()
        self.refreshList()

    def refreshList(self):
        self.accountsList.Clear()
        for account in self.plugin.getAccountNames():
            self.accountsList.Append(account)
        if self.accountsList.GetCount() > 0:
            self.accountsList.SetSelection(0)

    def onCopyToken(self, event):
        sel = self.accountsList.GetSelection()
        if sel == wx.NOT_FOUND:
            return
        name = self.accountsList.GetString(sel)
        if self.plugin.copyCodeForAccount(name):
            self.EndModal(wx.ID_OK)

    def _addFromOtpauthData(self, data):
        name = "{} ({})".format(data["issuer"], data["label"])

        if not generateTotp(data["secret"], data["digits"], data["period"], data["algorithm"]):
            wx.MessageBox(
                _("Invalid Base32 secret key found in the QR code / URI."),
                _("Error"), wx.OK | wx.ICON_ERROR, parent=self,
            )
            return False

        if name in self.plugin.getAccountNames():
            if (
                wx.MessageBox(
                    _("An account with this name already exists. Overwrite?"),
                    _("Confirm Overwrite"), wx.YES_NO | wx.ICON_QUESTION | wx.NO_DEFAULT, parent=self,
                )
                != wx.YES
            ):
                return False

        self.plugin.saveAccount(
            name, data["secret"], data["digits"], data["period"], data["algorithm"]
        )
        self.refreshList()
        return True

    def onAddAccount(self, event):
        choice = self._askAddMethod()
        if choice == "manual":
            self._addAccountManual()
        elif choice == "automatic":
            self._startAutomaticScan()
        # choice is None -> the chooser was cancelled, do nothing.

    def _askAddMethod(self):
        """Shows a small chooser dialog asking Manual vs Automatic.
        Returns "manual", "automatic", or None if cancelled."""
        result = {"choice": None}
        with wx.Dialog(self, title=_("Add 2FA Account")) as chooser:
            sizer = wx.BoxSizer(wx.VERTICAL)
            lbl = wx.StaticText(
                chooser,
                label=_("How would you like to add the account?"),
            )
            sizer.Add(lbl, 0, wx.ALL, 10)

            btnSizer = wx.BoxSizer(wx.HORIZONTAL)
            manualBtn = wx.Button(chooser, label=_("&Manual Entry..."))
            autoBtn = wx.Button(
                chooser, label=_("&Automatic (Scan QR on Screen)...")
            )
            cancelBtn = wx.Button(chooser, id=wx.ID_CANCEL, label=_("Cancel"))
            btnSizer.Add(manualBtn, 0, wx.ALL, 5)
            btnSizer.Add(autoBtn, 0, wx.ALL, 5)
            btnSizer.Add(cancelBtn, 0, wx.ALL, 5)
            sizer.Add(btnSizer, 0, wx.ALIGN_CENTER | wx.ALL, 10)

            def onManual(evt):
                result["choice"] = "manual"
                chooser.EndModal(wx.ID_OK)

            def onAuto(evt):
                result["choice"] = "automatic"
                chooser.EndModal(wx.ID_OK)

            manualBtn.Bind(wx.EVT_BUTTON, onManual)
            autoBtn.Bind(wx.EVT_BUTTON, onAuto)

            chooser.SetSizerAndFit(sizer)
            chooser.CenterOnScreen()
            manualBtn.SetFocus()
            chooser.ShowModal()

        return result["choice"]

    def _addAccountManual(self):
        msg = _(
            "Enter your 2FA context:\n"
            "You can paste either a secret key (Base32 format) or an 'otpauth://' URI link string."
        )
        with wx.TextEntryDialog(self, msg, _("Add 2FA Account")) as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                raw_input = dlg.GetValue().strip()
                if not raw_input:
                    return

                if raw_input.lower().startswith("otpauth://"):
                    data = parseOtpauthUri(raw_input)
                    if not data:
                        wx.MessageBox(
                            _("Invalid or unparseable otpauth format link."),
                            _("Error"), wx.OK | wx.ICON_ERROR, parent=self,
                        )
                        return
                    self._addFromOtpauthData(data)
                    return
                else:
                    with wx.TextEntryDialog(
                        self, _("Enter an identification name for this account:"), _("Account Name")
                    ) as nameDlg:
                        if nameDlg.ShowModal() != wx.ID_OK:
                            return
                        name = nameDlg.GetValue().strip()
                        if not name:
                            name = _("Manual Account")
                    secret = raw_input.replace(" ", "").upper()

                if not generateTotp(secret):
                    wx.MessageBox(
                        _("Invalid Base32 secret key provided."),
                        _("Error"), wx.OK | wx.ICON_ERROR, parent=self,
                    )
                    return

                if name in self.plugin.getAccountNames():
                    if (
                        wx.MessageBox(
                            _("An account with this name already exists. Overwrite?"),
                            _("Confirm Overwrite"), wx.YES_NO | wx.ICON_QUESTION | wx.NO_DEFAULT, parent=self,
                        )
                        != wx.YES
                    ):
                        return

                self.plugin.saveAccount(name, secret)
                self.refreshList()

    def _startAutomaticScan(self):
        if not QR_SUPPORT:
            self.plugin.promptAndDownloadQr(parent=self)
            return
        # Note: this is a modal dialog (opened via ShowModal). Calling
        # Hide() on a modal dialog on Windows is a known wx gotcha - it
        # can terminate the modal event loop early, causing ShowModal()
        # to return and the dialog to be Destroy()ed by its caller while
        # this scan is still "in flight". The delayed callback below
        # would then touch an already-deleted C++ object and crash.
        # SetTransparent(0) hides the window visually (the desktop
        # compositor reveals whatever is behind it, so the screenshot
        # still comes out clean) without ending the modal loop.
        self._hiddenForCapture = False
        try:
            if self.CanSetTransparent():
                self.SetTransparent(0)
                self._hiddenForCapture = True
            else:
                self.Hide()
        except RuntimeError:
            return
        ui.message(_("Scanning screen for a QR code..."))
        wx.CallLater(500, self._doScreenCapture)

    def _restoreAfterCapture(self):
        """Reverses _startAutomaticScan's visual hide. May raise RuntimeError
        if the dialog was closed in the meantime - callers should treat
        that as "nothing more to do here", not as an error to surface."""
        if getattr(self, "_hiddenForCapture", False):
            self.SetTransparent(255)
        else:
            self.Show()
        self.Raise()

    def _doScreenCapture(self):
        try:
            try:
                # all_screens=True (Pillow 9.2.0+) captures every
                # connected monitor, not just the primary one - without
                # it, a QR code on a second monitor is silently missed.
                pilImg = ImageGrab.grab(all_screens=True)
            except TypeError:
                pilImg = ImageGrab.grab()
            try:
                pilImg.save(DEBUG_SCREENSHOT_PATH)
            except Exception as e:
                log.debug("2FA Manager: could not save debug screenshot: {}".format(e))
            cvImg = pilImageToCvMat(pilImg)
            data = decodeQrFromImage(cvImg)
        except Exception as e:
            log.error("2FA Manager: Screen capture failed: {}".format(e))
            data = None

        try:
            self._restoreAfterCapture()
        except RuntimeError:
            # Dialog was closed/destroyed while the capture was running.
            return
        self._handleScannedData(data)

    def _handleScannedData(self, data):
        if not data:
            wx.MessageBox(
                _(
                    "No QR code could be found.\n\n"
                    "A copy of exactly what was captured has been saved to:\n{}\n\n"
                    "Open that file to check whether the code was captured "
                    "correctly (e.g. clear and in frame) or not (e.g. blank, "
                    "wrong area, or covered by another window)."
                ).format(DEBUG_SCREENSHOT_PATH),
                _("Scan Failed"), wx.OK | wx.ICON_INFORMATION, parent=self,
            )
            return

        if not data.lower().startswith("otpauth://"):
            wx.MessageBox(
                _("The QR code found is not a valid otpauth 2FA code."),
                _("Scan Failed"), wx.OK | wx.ICON_ERROR, parent=self,
            )
            return

        parsed = parseOtpauthUri(data)
        if not parsed:
            wx.MessageBox(
                _("The otpauth QR code could not be parsed."),
                _("Scan Failed"), wx.OK | wx.ICON_ERROR, parent=self,
            )
            return

        if self._addFromOtpauthData(parsed):
            ui.message(_("Account added from QR code: {}").format(
                "{} ({})".format(parsed["issuer"], parsed["label"])
            ))

    def onDeleteAccount(self, event):
        sel = self.accountsList.GetSelection()
        if sel == wx.NOT_FOUND:
            return
        name = self.accountsList.GetString(sel)
        confirm_msg = _("Are you absolutely sure you want to delete the 2FA entry: {}?").format(name)
        if (
            wx.MessageBox(
                confirm_msg, _("Confirm Deletion"), wx.YES_NO | wx.ICON_QUESTION | wx.NO_DEFAULT, parent=self
            )
            == wx.YES
        ):
            self.plugin.deleteAccount(name)
            self.refreshList()

    def onExportBackup(self, event):
        accounts = self.plugin.getAllAccountsRaw()
        if not accounts:
            wx.MessageBox(
                _("No accounts available to export."),
                _("Export Failed"), wx.OK | wx.ICON_INFORMATION, parent=self,
            )
            return

        with wx.FileDialog(
            self,
            message=_("Export 2FA Accounts Backup"),
            defaultDir="",
            defaultFile="2FA_Backup.json",
            wildcard="JSON files (*.json)|*.json",
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return

            path = fileDialog.GetPath()
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(accounts, f, indent=4, ensure_ascii=False)
                wx.MessageBox(
                    _("Accounts successfully exported to {}").format(path),
                    _("Export Successful"), wx.OK | wx.ICON_INFORMATION, parent=self,
                )
            except Exception as e:
                log.error("2FA Manager: Export failed: {}".format(e))
                wx.MessageBox(
                    _("Failed to export accounts: {}").format(e),
                    _("Error"), wx.OK | wx.ICON_ERROR, parent=self,
                )

    def onImportBackup(self, event):
        with wx.FileDialog(
            self,
            message=_("Import 2FA Accounts Backup"),
            defaultDir="",
            defaultFile="",
            wildcard="JSON files (*.json)|*.json",
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return

            path = fileDialog.GetPath()
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if not isinstance(data, dict):
                    raise ValueError(_("Invalid backup file format."))

                imported_count = 0
                for name, value in data.items():
                    if not isinstance(name, str):
                        continue

                    if isinstance(value, str):
                        secret = value.strip().replace(" ", "").upper()
                        digits, period, algorithm = 6, 30, "SHA1"
                    elif isinstance(value, dict) and "secret" in value:
                        secret = value["secret"].strip().replace(" ", "").upper()
                        digits = int(value.get("digits", 6))
                        period = int(value.get("period", 30))
                        algorithm = value.get("algorithm", "SHA1").upper()
                    else:
                        continue

                    if generateTotp(secret, digits, period, algorithm):
                        self.plugin.saveAccount(name, secret, digits, period, algorithm)
                        imported_count += 1

                self.refreshList()
                wx.MessageBox(
                    _("Successfully imported {} account(s).").format(imported_count),
                    _("Import Successful"), wx.OK | wx.ICON_INFORMATION, parent=self,
                )
            except Exception as e:
                log.error("2FA Manager: Import failed: {}".format(e))
                wx.MessageBox(
                    _("Failed to import accounts: {}").format(e),
                    _("Error"), wx.OK | wx.ICON_ERROR, parent=self,
                )


class GlobalPlugin(globalPluginHandler.GlobalPlugin):
    scriptCategory = _("2-Factor Authenticator")

    def __init__(self):
        super().__init__()
        conf_dir = globalVars.appArgs.configPath
        self.config_file = os.path.join(conf_dir, "two_factor_auth.ini")
        self.config = ConfigObj(self.config_file, encoding="utf-8")
        self._dialog = None

        if "accounts" not in self.config:
            self.config["accounts"] = {}
            self.config.write()

        # --- Tools menu: NVDA menu > Tools > 2FA > ... -------------------
        self.toolsMenu = gui.mainFrame.sysTrayIcon.toolsMenu
        self.subMenu = wx.Menu()

        manageItem = self.subMenu.Append(wx.ID_ANY, _("&Manage Accounts..."))
        gui.mainFrame.sysTrayIcon.Bind(wx.EVT_MENU, self.onManageAccounts, manageItem)

        reinstallItem = self.subMenu.Append(wx.ID_ANY, _("&Reinstall QR Library"))
        gui.mainFrame.sysTrayIcon.Bind(wx.EVT_MENU, self.onReinstallLibrary, reinstallItem)

        self.menuItem = self.toolsMenu.AppendSubMenu(self.subMenu, _("2FA"))

        # --- Ask about QR support once NVDA has fully started ------------
        try:
            core.postNvdaStartup.register(self.onNvdaStartupComplete)
            self._usingStartupHook = True
        except Exception:
            self._usingStartupHook = False
            wx.CallLater(5000, self.onNvdaStartupComplete)

    def terminate(self):
        try:
            if self._usingStartupHook:
                core.postNvdaStartup.unregister(self.onNvdaStartupComplete)
        except Exception:
            pass
        try:
            self.toolsMenu.Remove(self.menuItem.Id)
        except Exception:
            pass

    # --- Account storage --------------------------------------------------

    def getAccountNames(self):
        return sorted(list(self.config["accounts"].keys()))

    def _decodeEntry(self, raw):
        """Old entries were stored as a plain secret string. New entries
        are stored as a JSON string so digits/period/algorithm survive."""
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "secret" in data:
                return data
        except (ValueError, TypeError):
            pass
        return {"secret": raw, "digits": 6, "period": 30, "algorithm": "SHA1"}

    def getAllAccountsRaw(self):
        """Returns {name: {secret, digits, period, algorithm}} for export."""
        result = {}
        for name, raw in self.config["accounts"].items():
            result[name] = self._decodeEntry(raw)
        return result

    def generateTokenFor(self, name):
        raw = self.config["accounts"].get(name)
        if not raw:
            return None
        entry = self._decodeEntry(raw)
        return generateTotp(entry["secret"], entry["digits"], entry["period"], entry["algorithm"])

    def saveAccount(self, name, secret, digits=6, period=30, algorithm="SHA1"):
        entry = {"secret": secret, "digits": digits, "period": period, "algorithm": algorithm}
        self.config["accounts"][name] = json.dumps(entry)
        self.config.write()

    def deleteAccount(self, name):
        if name in self.config["accounts"]:
            del self.config["accounts"][name]
            self.config.write()

    def copyCodeForAccount(self, name):
        """Generates and copies the code for name. Returns True on success."""
        token = self.generateTokenFor(name)
        if token and api.copyToClip(token, notify=False):
            ui.message(_("Code copied to clipboard: {}").format(token))
            return True
        ui.message(_("Error generating code for this account. Check your secret key."))
        return False

    # --- Gesture: quick copy ----------------------------------------------

    @script(
        description=_("Copies a TOTP code for a saved 2FA account to the clipboard."),
        gesture="kb:nvda+control+2",
    )
    def script_copyCode(self, gesture):
        names = self.getAccountNames()
        if not names:
            ui.message(_(
                "No saved 2FA accounts. Open the 2FA Manager from the "
                "Tools menu to add one."
            ))
            return
        if len(names) == 1:
            self.copyCodeForAccount(names[0])
            return
        wx.CallAfter(self._presentQuickCopy)

    def _presentQuickCopy(self):
        gui.mainFrame.prePopup()
        dlg = QuickCopyDialog(gui.mainFrame, self)
        dlg.ShowModal()
        dlg.Destroy()
        gui.mainFrame.postPopup()

    # --- Tools menu handlers ------------------------------------------------

    def onManageAccounts(self, event):
        if self._dialog:
            self._dialog.Raise()
            return
        wx.CallAfter(self._presentManager)

    def _presentManager(self):
        gui.mainFrame.prePopup()
        self._dialog = AuthenticatorDialog(gui.mainFrame, self)
        self._dialog.ShowModal()
        self._dialog.Destroy()
        self._dialog = None
        gui.mainFrame.postPopup()

    def onReinstallLibrary(self, event):
        if QR_SUPPORT:
            answer = wx.MessageBox(
                _(
                    "QR support already appears to be installed. "
                    "Download and reinstall it again anyway?"
                ),
                _("Reinstall QR Library"), wx.YES_NO | wx.ICON_QUESTION, parent=gui.mainFrame,
            )
            if answer != wx.YES:
                return
        self.promptAndDownloadQr(parent=gui.mainFrame, skipInitialConfirm=True)

    # --- QR dependency prompt/download flow ---------------------------------

    def _isQrDeclined(self):
        return self.config.get("qrDownloadDeclined", "0") == "1"

    def _setQrDeclined(self, value):
        self.config["qrDownloadDeclined"] = "1" if value else "0"
        self.config.write()

    def onNvdaStartupComplete(self):
        if QR_SUPPORT or self._isQrDeclined():
            return
        wx.CallAfter(self.promptAndDownloadQr, gui.mainFrame, False)

    def promptAndDownloadQr(self, parent, skipInitialConfirm=False):
        if not skipInitialConfirm:
            answer = wx.MessageBox(
                _(
                    "QR scanning needs some extra components (roughly "
                    "40-60 MB) that are not bundled with this addon. "
                    "Download them now? This requires an internet connection."
                ),
                _("Download QR Support?"), wx.YES_NO | wx.ICON_QUESTION, parent=parent,
            )
            if answer != wx.YES:
                # Declining here is remembered permanently - NVDA will not
                # ask again automatically. It can always be retried from
                # Tools > 2FA > Reinstall QR Library.
                self._setQrDeclined(True)
                wx.MessageBox(
                    _(
                        "OK, QR scanning will stay disabled. You can install "
                        "it later from: NVDA menu > Tools > 2FA > "
                        "Reinstall QR Library."
                    ),
                    _("QR Support Not Installed"), wx.OK | wx.ICON_INFORMATION, parent=parent,
                )
                return

        cancelEvent = threading.Event()
        progressDlg = wx.ProgressDialog(
            _("Downloading QR Support"),
            _("Starting download..."),
            maximum=100,
            parent=parent,
            style=wx.PD_APP_MODAL | wx.PD_CAN_ABORT | wx.PD_AUTO_HIDE | wx.PD_SMOOTH,
        )

        def onProgress(percent, message):
            cont, skip = progressDlg.Update(min(percent, 100), message)
            if not cont:
                answer = wx.MessageBox(
                    _("Are you sure you want to cancel the download?"),
                    _("Cancel Download?"), wx.YES_NO | wx.ICON_WARNING, parent=progressDlg,
                )
                if answer == wx.YES:
                    cancelEvent.set()
                else:
                    try:
                        progressDlg.Resume()
                    except AttributeError:
                        pass

        def onDone(success, error):
            progressDlg.Destroy()
            if success:
                tryImportQrLibs()
                answer = wx.MessageBox(
                    _(
                        "QR support downloaded successfully. "
                        "Restart NVDA now to enable QR scanning?"
                    ),
                    _("Restart NVDA?"), wx.YES_NO | wx.ICON_QUESTION, parent=parent,
                )
                if answer == wx.YES:
                    core.restart()
                else:
                    ui.message(_("Please restart NVDA later to enable QR scanning."))
            elif error == "Cancelled":
                ui.message(_("QR support download cancelled."))
            else:
                wx.MessageBox(
                    _(
                        "Could not download QR support:\n{}\n\n"
                        "You can try again from: NVDA menu > Tools > 2FA > "
                        "Reinstall QR Library."
                    ).format(error or _("Unknown error.")),
                    _("Download Failed"), wx.OK | wx.ICON_ERROR, parent=parent,
                )

        downloadQrLibsAsync(onProgress, onDone, cancelEvent)
