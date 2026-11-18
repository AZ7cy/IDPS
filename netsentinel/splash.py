"""Startup splash screen and application icon, both from netsentinel/assets/logo.png."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QIcon, QLinearGradient, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import QApplication, QSplashScreen

from .config import APP_NAME

ASSETS = Path(__file__).resolve().parent / 'assets'
LOGO_PATH = ASSETS / 'logo.png'
SPLASH_WIDTH = 520              # logo width on the splash, in pixels
LOGO_PADDING = 18               # space between the logo and the frame
STATUS_HEIGHT = 74              # strip under the logo for the app name, progress bar and message
MIN_SPLASH_SECONDS = 1.5        # keep the logo up long enough to be seen, even on a fast start
ORANGE, PURPLE, DARK = QColor('#f97316'), QColor('#8b5cf6'), QColor('#0b1220')


def logo_pixmap() -> Optional[QPixmap]:
    """The logo, or None when the file is missing or not an image."""
    if not LOGO_PATH.is_file():
        return None
    pixmap = QPixmap(str(LOGO_PATH))
    return None if pixmap.isNull() else pixmap


def app_icon() -> QIcon:
    """Window, taskbar and tray icon. Empty when there is no logo, so Qt keeps its default."""
    pixmap = logo_pixmap()
    if pixmap is None:
        return QIcon()
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(pixmap.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio,
                                     Qt.TransformationMode.SmoothTransformation))
    return icon


def set_windows_app_id():
    """Make Windows show our icon on the taskbar instead of python.exe's."""
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('NetSentinel.IDPS')
    except Exception:
        pass


class Splash(QSplashScreen):
    """Logo with a progress bar and the current loading step underneath."""

    def __init__(self):
        logo = logo_pixmap()
        if logo is not None:
            # Fit the whole logo: SPLASH_WIDTH wide, but never taller than 70% of the screen.
            screen = QApplication.primaryScreen()
            max_h = int(screen.availableGeometry().height() * 0.7) - STATUS_HEIGHT if screen else 10_000
            logo = logo.scaled(SPLASH_WIDTH - 2 * LOGO_PADDING, max(120, max_h - 2 * LOGO_PADDING),
                               Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        self.logo = logo
        self.logo_height = logo.height() + 2 * LOGO_PADDING if logo is not None else 260
        base = QPixmap(SPLASH_WIDTH, self.logo_height + STATUS_HEIGHT)
        base.fill(DARK)
        super().__init__(base, Qt.WindowType.WindowStaysOnTopHint)
        self.message = 'Starting...'
        self.progress = 0.0
        self.started = time.monotonic()

    def step(self, message: str, progress: float):
        """Show a loading step; `progress` is 0..1."""
        self.message, self.progress = message, max(0.0, min(1.0, progress))
        self.repaint()
        app = QApplication.instance()
        if app is not None:
            app.processEvents()

    def drawContents(self, p: Optional[QPainter]):
        if p is None:
            return
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        if self.logo is not None:
            p.drawPixmap((w - self.logo.width()) // 2, LOGO_PADDING, self.logo)
        else:                                   # no logo file: a plain title card
            p.setPen(ORANGE)
            p.setFont(QFont('Segoe UI', 30, QFont.Weight.Bold))
            p.drawText(QRectF(0, 0, w, self.logo_height), Qt.AlignmentFlag.AlignCenter, 'IDPS')
        strip = QRectF(0, self.logo_height, w, STATUS_HEIGHT)
        p.fillRect(strip, DARK)
        p.setPen(QColor('#e7edf7'))
        p.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        p.drawText(QRectF(18, strip.y() + 8, w - 36, 22), Qt.AlignmentFlag.AlignLeft, APP_NAME)
        bar = QRectF(18, strip.y() + 36, w - 36, 6)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor('#1f2a3d'))
        p.drawRoundedRect(bar, 3, 3)
        if self.progress > 0:
            fill = QRectF(bar.x(), bar.y(), bar.width() * self.progress, bar.height())
            grad = QLinearGradient(fill.topLeft(), fill.topRight())
            grad.setColorAt(0, PURPLE)
            grad.setColorAt(1, ORANGE)
            p.setBrush(grad)
            p.drawRoundedRect(fill, 3, 3)
        p.setPen(QColor('#9fb0c8'))
        p.setFont(QFont('Segoe UI', 9))
        p.drawText(QRectF(18, strip.y() + 46, w - 36, 20), Qt.AlignmentFlag.AlignLeft, self.message)
        p.setPen(QPen(ORANGE, 2))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRect(QRectF(1, 1, w - 2, self.height() - 2))

    def finish_after_minimum(self, window):
        """Close once `window` is shown, but not before MIN_SPLASH_SECONDS have passed."""
        app = QApplication.instance()
        while time.monotonic() - self.started < MIN_SPLASH_SECONDS:
            if app is not None:
                app.processEvents()
            time.sleep(0.02)
        self.finish(window)
