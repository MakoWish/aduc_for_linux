#!/usr/bin/env python3
from __future__ import annotations

import csv
import inspect
import base64
import json
import os
import ssl
import struct
import sys
import urllib.error
import urllib.request
import ldap3
import webbrowser
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional
from contextlib import contextmanager

from PySide6.QtCore import QDateTime, QMimeData, QObject, QPoint, QThread, Signal, Qt, QTimer, QEventLoop, QPropertyAnimation, QEasingCurve, Property
from PySide6.QtGui import QAction, QBrush, QColor, QDrag, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QMenu,
    QInputDialog,
    QDialog,
    QButtonGroup,
    QDialogButtonBox,
    QDateTimeEdit,
    QFileDialog,
    QAbstractItemView,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QRadioButton,
    QSplitter,
    QStyle,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTimeEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QSplashScreen,
)

from ldap3 import ALL, BASE, LEVEL, SUBTREE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SASL, Connection, Server, Tls

try:
    import keyring
except Exception:
    keyring = None


# Hard-coded values used only during development
TEST_DC = ""
TEST_BIND_USER = ""
TEST_BIND_PASSWORD = ""

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "aduc-linux")
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")
VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
SPLASH_IMAGE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "image.png")
SPLASH_IMAGE_SIZE = 500
SPLASH_FADE_DURATION_MS = 1400
REMOTE_VERSION_URL = "https://raw.githubusercontent.com/MakoWish/aduc_for_linux/main/VERSION"
UPDATE_COMMAND = "bash <(wget -qO- https://raw.githubusercontent.com/MakoWish/aduc_for_linux/main/install.sh)"

CONTAINER_CLASSES = {
    "domain",
    "container",
    "organizationalunit",
    "builtindomain",
}

USER_CLASSES = {"user", "person", "organizationalperson"}
GROUP_CLASSES = {"group"}
COMPUTER_CLASSES = {"computer"}

CREATABLE_CHILD_CLASS_BY_ACTION = {
    "user": "user",
    "group": "group",
    "computer": "computer",
    "organizational_unit": "organizationalunit",
}

SEARCH_FILTER_USERS_CONTACTS_GROUPS = "users_contacts_groups"
SEARCH_FILTER_COMPUTERS = "computers"
SEARCH_FILTER_ORGANIZATIONAL_UNITS = "organizational_units"
SEARCH_FILTER_GROUPS = "groups"

SEARCH_FILTER_OPTIONS = [
    ("Users, Contacts, and Groups", SEARCH_FILTER_USERS_CONTACTS_GROUPS),
    ("Computers", SEARCH_FILTER_COMPUTERS),
    ("Organizational Units", SEARCH_FILTER_ORGANIZATIONAL_UNITS),
]

KEYRING_SERVICE_NAME = "aduc-for-linux"



@dataclass
class ConnectionProfile:
    name: str
    host: str
    port: int
    auth_mode: str
    bind_user: str
    store_password: bool = False


class CredentialStore:
    @staticmethod
    def available() -> bool:
        return keyring is not None

    @staticmethod
    def _secret_name(profile_name: str) -> str:
        return f"profile:{profile_name}"

    @classmethod
    def get_password(cls, profile_name: str) -> str:
        if keyring is None:
            return ""
        try:
            value = keyring.get_password(KEYRING_SERVICE_NAME, cls._secret_name(profile_name))
            return value or ""
        except Exception:
            return ""

    @classmethod
    def set_password(cls, profile_name: str, password: str) -> bool:
        if keyring is None:
            return False
        try:
            keyring.set_password(KEYRING_SERVICE_NAME, cls._secret_name(profile_name), password)
            return True
        except Exception:
            return False

    @classmethod
    def delete_password(cls, profile_name: str) -> None:
        if keyring is None:
            return
        try:
            keyring.delete_password(KEYRING_SERVICE_NAME, cls._secret_name(profile_name))
        except Exception:
            pass


WELL_KNOWN_SID_LABELS = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-4": "Owner Rights",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "LOCAL SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\Local Service",
    "S-1-5-20": "NT AUTHORITY\\Network Service",
}


CREATOR_SIDS = {"S-1-3-0", "S-1-3-1"}
CREATOR_INHERIT_ACE_FLAGS = 0x0B  # OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE


@contextmanager
def busy_cursor() -> Any:
    QApplication.setOverrideCursor(Qt.WaitCursor)
    QApplication.processEvents(QEventLoop.AllEvents, 50)
    try:
        yield
    finally:
        QApplication.restoreOverrideCursor()

def parse_sid(sid_bytes: bytes) -> str:
    if len(sid_bytes) < 8:
        return "<invalid SID>"
    revision = sid_bytes[0]
    sub_count = sid_bytes[1]
    needed = 8 + (4 * sub_count)
    if len(sid_bytes) < needed:
        return "<invalid SID>"
    identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder="big", signed=False)
    subs = [struct.unpack("<I", sid_bytes[8 + 4 * i: 12 + 4 * i])[0] for i in range(sub_count)]
    return f"S-{revision}-{identifier_authority}" + "".join(f"-{value}" for value in subs)


def sid_to_bytes(sid: str) -> bytes:
    parts = sid.strip().split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        raise ValueError(f"Invalid SID: {sid}")

    revision = int(parts[1])
    identifier_authority = int(parts[2])
    sub_authorities = [int(x) for x in parts[3:]]

    if revision < 0 or revision > 255:
        raise ValueError(f"Invalid SID revision: {revision}")
    if identifier_authority < 0 or identifier_authority > 0xFFFFFFFFFFFF:
        raise ValueError(f"Invalid SID identifier authority: {identifier_authority}")
    if len(sub_authorities) > 255:
        raise ValueError("SID has too many sub-authorities")

    head = bytes([revision, len(sub_authorities)]) + identifier_authority.to_bytes(6, byteorder="big", signed=False)
    body = b"".join(struct.pack("<I", value) for value in sub_authorities)
    return head + body


def parse_relative_security_descriptor(sd_bytes: bytes) -> dict[str, Any]:
    out = {
        "owner_sid": "",
        "group_sid": "",
        "dacl": [],
        "error": "",
    }
    if len(sd_bytes) < 20:
        out["error"] = "Descriptor is shorter than SECURITY_DESCRIPTOR header."
        return out

    try:
        revision, _sbz1, control, owner_off, group_off, _sacl_off, dacl_off = struct.unpack("<BBHLLLL", sd_bytes[:20])
    except struct.error:
        out["error"] = "Unable to parse SECURITY_DESCRIPTOR header."
        return out

    if revision != 1:
        out["error"] = f"Unexpected security descriptor revision: {revision}"

    out["control"] = int(control)

    def _read_sid(offset: int) -> str:
        if offset <= 0 or offset >= len(sd_bytes):
            return ""
        sub_count = sd_bytes[offset + 1] if offset + 1 < len(sd_bytes) else 0
        sid_size = 8 + (4 * sub_count)
        if offset + sid_size > len(sd_bytes):
            return "<invalid SID>"
        return parse_sid(sd_bytes[offset: offset + sid_size])

    out["owner_sid"] = _read_sid(owner_off)
    out["group_sid"] = _read_sid(group_off)

    if dacl_off <= 0 or dacl_off + 8 > len(sd_bytes):
        return out

    ace_type_map = {
        0x00: "ACCESS_ALLOWED",
        0x01: "ACCESS_DENIED",
        0x02: "SYSTEM_AUDIT",
        0x03: "SYSTEM_ALARM",
        0x05: "ACCESS_ALLOWED_OBJECT",
        0x06: "ACCESS_DENIED_OBJECT",
    }

    dacl_data = sd_bytes[dacl_off:]
    try:
        _acl_rev, _acl_sbz1, acl_size, ace_count, _acl_sbz2 = struct.unpack("<BBHHH", dacl_data[:8])
    except struct.error:
        out["error"] = "Unable to parse DACL header."
        return out

    if acl_size > len(dacl_data):
        acl_size = len(dacl_data)

    cursor = 8
    for _ in range(ace_count):
        if cursor + 8 > acl_size:
            break
        ace_type = dacl_data[cursor]
        ace_flags = dacl_data[cursor + 1]
        ace_size = struct.unpack("<H", dacl_data[cursor + 2: cursor + 4])[0]
        if ace_size <= 0 or cursor + ace_size > acl_size:
            break

        ace_bytes = dacl_data[cursor: cursor + ace_size]
        mask = struct.unpack("<I", ace_bytes[4:8])[0] if len(ace_bytes) >= 8 else 0
        sid = ""

        sid_offset = 8
        if ace_type in (0x05, 0x06) and len(ace_bytes) >= 12:
            # ACCESS_ALLOWED_OBJECT_ACE / ACCESS_DENIED_OBJECT_ACE:
            # ACE header (4) + mask (4) + flags (4) + optional GUIDs + SID.
            object_flags = struct.unpack("<I", ace_bytes[8:12])[0]
            sid_offset = 12
            if object_flags & 0x1:
                sid_offset += 16
            if object_flags & 0x2:
                sid_offset += 16

        if len(ace_bytes) > sid_offset:
            sid = parse_sid(ace_bytes[sid_offset:])

        out["dacl"].append(
            {
                "type": ace_type_map.get(ace_type, f"ACE_{ace_type}"),
                "ace_type": int(ace_type),
                "flags": f"0x{ace_flags:02X}",
                "ace_flags": int(ace_flags),
                "mask": f"0x{mask:08X}",
                "mask_value": int(mask),
                "trustee_sid": sid,
            }
        )

        cursor += ace_size

    _ = control
    return out


def parse_version(version: str) -> tuple[int, ...]:
    normalized = version.strip().lstrip("vV")
    parts = []
    for chunk in normalized.split("."):
        digits = ""
        for char in chunk:
            if char.isdigit():
                digits += char
            else:
                break
        parts.append(int(digits or 0))
    return tuple(parts)


def is_newer_version(current_version: str, remote_version: str) -> bool:
    current_parts = parse_version(current_version)
    remote_parts = parse_version(remote_version)
    width = max(len(current_parts), len(remote_parts))
    current_padded = current_parts + (0,) * (width - len(current_parts))
    remote_padded = remote_parts + (0,) * (width - len(remote_parts))
    return remote_padded > current_padded


def read_local_version() -> str:
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as handle:
            version = handle.read().strip()
            return version or "0.0.0"
    except OSError:
        return "0.0.0"


def fetch_remote_version(timeout: float = 3.0) -> Optional[str]:
    try:
        with urllib.request.urlopen(REMOTE_VERSION_URL, timeout=timeout) as response:
            payload = response.read().decode("utf-8").strip()
            return payload or None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def build_aduc_ou_icon(has_child_ou: bool, size: int = 16) -> QIcon:
    """Create a Windows ADUC-style OU icon.

    OUs with child OUs receive a stacked card treatment; leaf OUs use a single card.
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, False)

    scale = max(1, size // 16)

    folder_tab_rect = (1 * scale, 2 * scale, 6 * scale, 3 * scale)
    folder_body_rect = (1 * scale, 4 * scale, 14 * scale, 10 * scale)
    back_card_rect = (7 * scale, 6 * scale, 6 * scale, 6 * scale)
    card_rect = (8 * scale, 7 * scale, 7 * scale, 7 * scale)

    folder_border = QColor("#9A6900")
    folder_fill = QColor("#F7CF5A")
    folder_tab_fill = QColor("#FCE08E")
    card_border = QColor("#2E5590")
    card_fill = QColor("#BBD6FF")

    painter.setPen(QPen(folder_border, 1))
    painter.setBrush(QBrush(folder_tab_fill))
    painter.drawRect(*folder_tab_rect)

    painter.setBrush(QBrush(folder_fill))
    painter.drawRect(*folder_body_rect)

    if has_child_ou:
        painter.setPen(QPen(card_border, 1))
        painter.setBrush(QBrush(QColor("#D9E8FF")))
        painter.drawRect(*back_card_rect)

    painter.setPen(QPen(card_border, 1))
    painter.setBrush(QBrush(card_fill))
    painter.drawRect(*card_rect)

    painter.setPen(QPen(card_border, 1))
    line_y = card_rect[1] + 2 * scale
    for _ in range(3):
        painter.drawLine(card_rect[0] + 1 * scale, line_y, card_rect[0] + card_rect[2] - 2 * scale, line_y)
        line_y += 2 * scale

    painter.end()
    return QIcon(pixmap)


def build_aduc_container_icon(size: int = 16) -> QIcon:
    """Create an ADUC-like plain folder icon for generic containers."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, False)

    scale = max(1, size // 16)

    folder_tab_rect = (1 * scale, 2 * scale, 7 * scale, 3 * scale)
    folder_body_rect = (1 * scale, 4 * scale, 14 * scale, 10 * scale)

    folder_border = QColor("#9A6900")
    folder_fill = QColor("#F7CF5A")
    folder_tab_fill = QColor("#FCE08E")

    painter.setPen(QPen(folder_border, 1))
    painter.setBrush(QBrush(folder_tab_fill))
    painter.drawRect(*folder_tab_rect)

    painter.setBrush(QBrush(folder_fill))
    painter.drawRect(*folder_body_rect)

    painter.end()
    return QIcon(pixmap)


def build_aduc_user_icon(size: int = 16) -> QIcon:
    """Create an ADUC-like user icon (person over blue account card)."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)

    scale = max(1, size // 16)

    card_rect = (6 * scale, 6 * scale, 9 * scale, 8 * scale)
    painter.setPen(QPen(QColor("#2E5590"), 1))
    painter.setBrush(QBrush(QColor("#C8DCFF")))
    painter.drawRect(*card_rect)

    painter.setPen(QPen(QColor("#2E5590"), 1))
    for i in range(3):
        y = card_rect[1] + (2 + 2 * i) * scale
        painter.drawLine(card_rect[0] + 1 * scale, y, card_rect[0] + card_rect[2] - 2 * scale, y)

    painter.setPen(QPen(QColor("#7A4F1A"), 1))
    painter.setBrush(QBrush(QColor("#F6D1A2")))
    painter.drawEllipse(1 * scale, 2 * scale, 6 * scale, 6 * scale)

    painter.setPen(QPen(QColor("#315C9C"), 1))
    painter.setBrush(QBrush(QColor("#4F83C5")))
    painter.drawRoundedRect(1 * scale, 8 * scale, 7 * scale, 6 * scale, 1, 1)

    painter.end()
    return QIcon(pixmap)


def build_aduc_group_icon(size: int = 16) -> QIcon:
    """Create an ADUC-like group icon (two user heads over card)."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)

    scale = max(1, size // 16)
    painter.setPen(QPen(QColor("#2E5590"), 1))
    painter.setBrush(QBrush(QColor("#C8DCFF")))
    painter.drawRect(6 * scale, 6 * scale, 9 * scale, 8 * scale)

    painter.setPen(QPen(QColor("#845A21"), 1))
    painter.setBrush(QBrush(QColor("#F2C996")))
    painter.drawEllipse(1 * scale, 3 * scale, 4 * scale, 4 * scale)
    painter.drawEllipse(4 * scale, 2 * scale, 4 * scale, 4 * scale)

    painter.setPen(QPen(QColor("#2E6FAE"), 1))
    painter.setBrush(QBrush(QColor("#5A9AD6")))
    painter.drawRoundedRect(1 * scale, 8 * scale, 4 * scale, 5 * scale, 1, 1)
    painter.drawRoundedRect(4 * scale, 7 * scale, 4 * scale, 6 * scale, 1, 1)

    painter.end()
    return QIcon(pixmap)


def build_aduc_computer_icon(size: int = 16) -> QIcon:
    """Create an ADUC-like computer icon (CRT monitor + base)."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, False)

    scale = max(1, size // 16)
    painter.setPen(QPen(QColor("#4A4A4A"), 1))
    painter.setBrush(QBrush(QColor("#DCE3EC")))
    painter.drawRect(2 * scale, 2 * scale, 12 * scale, 9 * scale)

    painter.setPen(QPen(QColor("#2B577E"), 1))
    painter.setBrush(QBrush(QColor("#8EC1F0")))
    painter.drawRect(3 * scale, 3 * scale, 10 * scale, 7 * scale)

    painter.setPen(QPen(QColor("#6A6A6A"), 1))
    painter.setBrush(QBrush(QColor("#A9B3BF")))
    painter.drawRect(6 * scale, 11 * scale, 4 * scale, 2 * scale)
    painter.drawRect(4 * scale, 13 * scale, 8 * scale, 2 * scale)

    painter.end()
    return QIcon(pixmap)


def build_application_icon() -> QIcon:
    """Load the application icon from app_icon.png in the project directory."""
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_icon.png")
    icon = QIcon(icon_path)
    return icon if not icon.isNull() else QIcon.fromTheme("applications-system")


def icon_for_directory_object(style, obj: LdapObject) -> QIcon:
    if obj.object_type == "Organizational Unit":
        return build_aduc_ou_icon(has_child_ou=obj.has_child_ou)
    if obj.object_type in {"Container", "Domain"}:
        return build_aduc_container_icon()
    if obj.object_type == "User":
        base_icon = build_aduc_user_icon()
        return add_user_state_overlays(base_icon, obj)
    if obj.object_type == "Group":
        return build_aduc_group_icon()
    if obj.object_type == "Computer":
        base_icon = build_aduc_computer_icon()
        return add_computer_state_overlays(base_icon, obj)
    icon = QIcon.fromTheme("text-x-generic")
    return icon if not icon.isNull() else style.standardIcon(QStyle.SP_FileIcon)

def icon_for_object_classes(style, object_classes: list[str], has_child_ou: bool = False) -> QIcon:
    classes = [str(cls).lower() for cls in object_classes]
    obj = LdapObject(dn="", name="", object_classes=classes, has_child_ou=has_child_ou)
    return icon_for_directory_object(style, obj)


def add_user_state_overlays(base_icon: QIcon, obj: "LdapObject", size: int = 16) -> QIcon:
    """Overlay state badges onto user icons (disabled / locked)."""
    if not (obj.user_disabled or obj.user_locked):
        return base_icon

    pixmap = base_icon.pixmap(size, size)
    if pixmap.isNull():
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)

    if obj.user_disabled:
        painter.setPen(QPen(QColor("#B71C1C"), 2))
        painter.setBrush(QBrush(QColor("#FDECEC")))
        painter.drawEllipse(1, size - 8, 7, 7)
        painter.drawLine(2, size - 2, 7, size - 7)

    if obj.user_locked:
        lock_body = QColor("#D6A200")
        lock_outline = QColor("#7A5D00")
        painter.setPen(QPen(lock_outline, 1))
        painter.setBrush(QBrush(lock_body))
        painter.drawRect(size - 7, size - 7, 6, 5)
        painter.setBrush(Qt.NoBrush)
        painter.drawArc(size - 7, size - 10, 6, 6, 35 * 16, 110 * 16)

    painter.end()
    return QIcon(pixmap)


def add_computer_state_overlays(base_icon: QIcon, obj: "LdapObject", size: int = 16) -> QIcon:
    """Overlay state badges onto computer icons (disabled)."""
    if not obj.computer_disabled:
        return base_icon

    pixmap = base_icon.pixmap(size, size)
    if pixmap.isNull():
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)

    badge_size = 8
    badge_x = size - badge_size
    badge_y = size - badge_size

    painter.setPen(QPen(QColor("#B71C1C"), 1))
    painter.setBrush(QBrush(QColor("#D32F2F")))
    painter.drawEllipse(badge_x, badge_y, badge_size - 1, badge_size - 1)

    painter.setPen(QPen(QColor("#FFFFFF"), 2))
    painter.drawLine(badge_x + 2, badge_y + 2, badge_x + badge_size - 3, badge_y + badge_size - 3)
    painter.drawLine(badge_x + badge_size - 3, badge_y + 2, badge_x + 2, badge_y + badge_size - 3)

    painter.end()
    return QIcon(pixmap)


@dataclass
class LdapObject:
    dn: str
    name: str
    object_classes: list[str]
    description: str = ""
    user_disabled: bool = False
    user_locked: bool = False
    computer_disabled: bool = False
    has_child_ou: bool = False

    @property
    def is_container(self) -> bool:
        return any(cls in CONTAINER_CLASSES for cls in self.object_classes)

    @property
    def object_type(self) -> str:
        classes = set(self.object_classes)
        if any(cls in classes for cls in COMPUTER_CLASSES):
            return "Computer"
        if any(cls in classes for cls in GROUP_CLASSES):
            return "Group"
        if any(cls in classes for cls in USER_CLASSES) and "computer" not in classes:
            return "User"
        if "organizationalunit" in classes:
            return "Organizational Unit"
        if "container" in classes or "builtindomain" in classes:
            return "Container"
        if "domain" in classes:
            return "Domain"
        return "Object"


class LdapManager:
    def __init__(self) -> None:
        self.server: Optional[Server] = None
        self.conn: Optional[Connection] = None
        self.page_size = 500
        self._attribute_schema_cache: dict[str, dict[str, Any]] = {}

    def _paged_search_entries(
        self,
        search_base: str,
        search_filter: str,
        search_scope,
        attributes: list[str],
        size_limit: int = 0,
    ) -> list:
        if not self.conn:
            return []

        entries: list = []
        cookie: Optional[bytes] = None
        remaining = size_limit if size_limit and size_limit > 0 else None

        while True:
            page_size = self.page_size if remaining is None else min(self.page_size, remaining)
            if page_size <= 0:
                break

            self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attributes,
                paged_size=page_size,
                paged_cookie=cookie,
            )

            page_entries = list(self.conn.entries)
            entries.extend(page_entries)

            if remaining is not None:
                remaining -= len(page_entries)
                if remaining <= 0:
                    break

            controls = self.conn.result.get("controls", {})
            page_control = controls.get("1.2.840.113556.1.4.319", {})
            control_value = page_control.get("value", {}) if isinstance(page_control, dict) else {}
            cookie = control_value.get("cookie") if isinstance(control_value, dict) else None
            if not cookie:
                break

        return entries

    def connect_simple(self, host: str, bind_user: str, password: str, port: int = 636) -> None:
        tls = Tls(validate=ssl.CERT_REQUIRED)
        self.server = Server(host, port=port, use_ssl=True, get_info=ALL, tls=tls)
        self.conn = Connection(
            self.server,
            user=bind_user,
            password=password,
            auto_bind=True,
            raise_exceptions=True,
        )
        self._attribute_schema_cache.clear()

    def connect_kerberos(self, host: str, port: int = 636) -> None:
        tls = Tls(validate=ssl.CERT_REQUIRED)
        self.server = Server(host, port=port, use_ssl=True, get_info=ALL, tls=tls)
        kwargs = {
            "authentication": SASL,
            "sasl_mechanism": "GSSAPI",
            "auto_bind": True,
            "raise_exceptions": True,
        }
        encrypt_value = getattr(ldap3, "ENCRYPT", "ENCRYPT")
        supports_session_security = "session_security" in inspect.signature(Connection.__init__).parameters

        if supports_session_security:
            self.conn = Connection(self.server, session_security=encrypt_value, **kwargs)
            self._attribute_schema_cache.clear()
            return

        try:
            self.conn = Connection(self.server, **kwargs)
            self._attribute_schema_cache.clear()
        except Exception as e:
            message = str(e)
            if "Sign or Seal are required" in message:
                raise ValueError(
                    "Kerberos bind failed: this server requires SASL GSSAPI sign/seal, but ldap3 in this "
                    "application path cannot negotiate that security layer. Use credential authentication "
                    "for this domain, or relax the Samba LDAP strong-auth policy if acceptable in your environment."
                ) from e
            raise

    @staticmethod
    def _entry_attr_values(entry: Any, attr_name: str) -> list[str]:
        if attr_name not in entry:
            return []

        try:
            values = getattr(entry, attr_name).values
        except Exception:
            return []

        if not isinstance(values, list):
            values = [values]

        result: list[str] = []
        for value in values:
            v = str(value).strip()
            if v:
                result.append(v)
        return result

    def get_naming_contexts(self) -> list[str]:
        if not self.conn:
            return []

        self.conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["namingContexts"],
        )
        if not self.conn.entries:
            return []

        entry = self.conn.entries[0]
        contexts: list[str] = []

        for value in self._entry_attr_values(entry, "namingContexts"):
            if value not in contexts:
                contexts.append(value)

        return contexts

    def get_default_naming_context(self) -> Optional[str]:
        partitions = self.get_directory_partitions()
        default_nc = partitions.get("default_naming_context")
        if isinstance(default_nc, str) and default_nc.strip():
            return default_nc.strip()

        naming_contexts = self.get_naming_contexts()
        for context in naming_contexts:
            value = str(context).strip()
            if value and value.upper().startswith("DC="):
                return value

        for context in naming_contexts:
            value = str(context).strip()
            if value:
                return value

        return None

    def get_directory_partitions(self) -> dict[str, Any]:
        empty_partitions = {
            "default_naming_context": None,
            "root_domain_naming_context": None,
            "configuration_naming_context": None,
            "schema_naming_context": None,
            "domain_naming_contexts": [],
            "all_naming_contexts": [],
        }

        if not self.conn:
            return empty_partitions

        try:
            self.conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["*", "+"],
            )
        except Exception:
            # Non-AD LDAP servers may reject AD-specific RootDSE attributes.
            # Returning empty partition metadata preserves old fallback behavior.
            return empty_partitions

        if not self.conn.entries:
            return empty_partitions

        entry = self.conn.entries[0]
        default_nc = next(iter(self._entry_attr_values(entry, "defaultNamingContext")), None)
        root_domain_nc = next(iter(self._entry_attr_values(entry, "rootDomainNamingContext")), None)
        config_nc = next(iter(self._entry_attr_values(entry, "configurationNamingContext")), None)
        schema_nc = next(iter(self._entry_attr_values(entry, "schemaNamingContext")), None)
        naming_contexts = self._entry_attr_values(entry, "namingContexts")

        excluded = {x for x in [config_nc, schema_nc] if x}
        domain_ncs: list[str] = []
        for nc in naming_contexts:
            if nc in excluded:
                continue
            if nc.upper().startswith("DC="):
                domain_ncs.append(nc)

        return {
            "default_naming_context": default_nc,
            "root_domain_naming_context": root_domain_nc,
            "configuration_naming_context": config_nc,
            "schema_naming_context": schema_nc,
            "domain_naming_contexts": domain_ncs,
            "all_naming_contexts": naming_contexts,
        }

    def get_trusted_domains(self, base_dn: str) -> list[dict[str, str]]:
        if not self.conn or not base_dn:
            return []

        trusted_domains: list[dict[str, str]] = []
        system_dn = f"CN=System,{base_dn}"

        entries = self._paged_search_entries(
            search_base=system_dn,
            search_filter="(objectClass=trustedDomain)",
            search_scope=LEVEL,
            attributes=["name", "trustPartner", "flatName"],
        )

        for entry in entries:
            partners = self._entry_attr_values(entry, "trustPartner")
            if not partners:
                continue

            partner = partners[0]
            flat_name = next(iter(self._entry_attr_values(entry, "flatName")), "")
            trusted_domains.append(
                {
                    "partner": partner,
                    "flat_name": flat_name,
                }
            )

        trusted_domains.sort(key=lambda x: x["partner"].lower())
        return trusted_domains

    @staticmethod
    def _display_name(entry, object_classes: list[str], fallback: str) -> str:
        if "computer" in object_classes and "cn" in entry:
            try:
                cn_values = entry.cn.values
                cn = str(cn_values[0]) if isinstance(cn_values, list) and cn_values else str(cn_values)
            except Exception:
                cn = ""
            cn = cn.replace("\r", " ").replace("\n", " ").strip()
            if cn:
                return cn
        return str(entry.name) if "name" in entry else fallback

    def list_children(self, base_dn: str) -> list[LdapObject]:
        if not self.conn:
            return []

        entries = self._paged_search_entries(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            search_scope=LEVEL,
            attributes=[
                "distinguishedName",
                "name",
                "cn",
                "objectClass",
                "description",
                "userAccountControl",
                "lockoutTime",
            ],
        )

        results: list[LdapObject] = []
        for entry in entries:
            dn = str(entry.entry_dn)
            object_classes = [str(x).lower() for x in entry.objectClass.values] if "objectClass" in entry else []
            name = self._display_name(entry, object_classes, dn)
            description = ""
            if "description" in entry:
                try:
                    values = entry.description.values
                    if isinstance(values, list) and values:
                        description = str(values[0])
                    elif values:
                        description = str(values)
                except Exception:
                    description = ""

            results.append(
                LdapObject(
                    dn=dn,
                    name=name,
                    object_classes=object_classes,
                    description=description,
                    user_disabled=self._is_user_disabled(entry, object_classes),
                    user_locked=self._is_user_locked(entry, object_classes),
                    computer_disabled=self._is_computer_disabled(entry, object_classes),
                )
            )

        results.sort(key=lambda x: (not x.is_container, x.name.lower()))
        self._populate_ou_child_status(results)
        return results

    def get_object_attributes(self, dn: str) -> dict[str, list[str]]:
        if not self.conn:
            return {}

        self.conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["*"],
        )
        if not self.conn.entries:
            return {}

        entry = self.conn.entries[0]
        out: dict[str, list[str]] = {}

        for attr in entry.entry_attributes:
            try:
                values = entry[attr].values
                if isinstance(values, list):
                    out[attr] = [str(v) for v in values]
                else:
                    out[attr] = [str(values)]
            except Exception:
                out[attr] = ["<unreadable>"]

        return dict(sorted(out.items(), key=lambda kv: kv[0].lower()))

    def get_attribute_schema_info(self, attr_name: str) -> dict[str, Any]:
        cache_key = attr_name.lower()
        if cache_key in self._attribute_schema_cache:
            return dict(self._attribute_schema_cache[cache_key])
        empty = {"single_valued": None, "is_integer": None}
        if not self.conn:
            return dict(empty)

        partitions = self.get_directory_partitions()
        schema_nc = partitions.get("schema_naming_context")
        if not isinstance(schema_nc, str) or not schema_nc.strip():
            return dict(empty)

        escaped_name = ldap3.utils.conv.escape_filter_chars(attr_name)
        search_filter = f"(&(objectClass=attributeSchema)(lDAPDisplayName={escaped_name}))"

        try:
            self.conn.search(
                search_base=schema_nc,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["isSingleValued", "attributeSyntax", "oMSyntax"],
                size_limit=1,
            )
        except Exception:
            return dict(empty)

        if not self.conn.entries:
            return dict(empty)

        entry = self.conn.entries[0]
        single_valued_raw = next(iter(self._entry_attr_values(entry, "isSingleValued")), "")
        single_valued: Optional[bool]
        if single_valued_raw.lower() in {"true", "1"}:
            single_valued = True
        elif single_valued_raw.lower() in {"false", "0"}:
            single_valued = False
        else:
            single_valued = None

        syntax = next(iter(self._entry_attr_values(entry, "attributeSyntax")), "")
        om_syntax = next(iter(self._entry_attr_values(entry, "oMSyntax")), "")
        is_integer = syntax in {"2.5.5.9", "2.5.5.16", "2.5.5.6"} or om_syntax in {"2", "65"}

        info = {"single_valued": single_valued, "is_integer": is_integer}
        self._attribute_schema_cache[cache_key] = dict(info)
        return dict(info)

    def get_security_descriptor_details(self, dn: str) -> dict[str, Any]:
        if not self.conn:
            return {"error": "Not connected"}

        controls = None
        try:
            from ldap3.protocol.microsoft import security_descriptor_control

            controls = security_descriptor_control(sdflags=0x04)
        except Exception:
            controls = None

        try:
            self.conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["nTSecurityDescriptor"],
                controls=controls,
            )
        except Exception as e:
            return {"error": str(e)}

        if not self.conn.entries:
            return {"error": "Object not found"}

        entry = self.conn.entries[0]
        raw_values = []
        try:
            if "nTSecurityDescriptor" in entry:
                raw_values = entry["nTSecurityDescriptor"].raw_values
        except Exception:
            raw_values = []

        if not raw_values:
            return {"error": "nTSecurityDescriptor is unavailable for this object/connection."}

        value = raw_values[0]
        if not isinstance(value, (bytes, bytearray)):
            return {"error": "nTSecurityDescriptor returned in an unexpected format."}

        sd_bytes = bytes(value)
        parsed = parse_relative_security_descriptor(sd_bytes)
        parsed["base64"] = base64.b64encode(sd_bytes).decode("ascii")
        parsed["length"] = len(sd_bytes)
        parsed["raw_bytes"] = sd_bytes
        return parsed

    def set_security_descriptor(self, dn: str, sd_bytes: bytes) -> None:
        if not self.conn:
            raise ValueError("Not connected")

        controls = None
        try:
            from ldap3.protocol.microsoft import security_descriptor_control

            controls = security_descriptor_control(sdflags=0x04)
        except Exception:
            controls = None

        ok = self.conn.modify(
            dn,
            {"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd_bytes])]},
            controls=controls,
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def get_object_display_and_sid(self, dn: str) -> tuple[str, str]:
        if not self.conn:
            raise ValueError("Not connected")

        self.conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["displayName", "cn", "name", "objectSid"],
        )
        if not self.conn.entries:
            raise ValueError("Object not found")

        entry = self.conn.entries[0]
        display = dn
        for attr in ["displayName", "cn", "name"]:
            values = self._entry_attr_values(entry, attr)
            if values:
                display = values[0]
                break

        sid_values = []
        try:
            if "objectSid" in entry:
                sid_values = entry["objectSid"].raw_values
        except Exception:
            sid_values = []
        if not sid_values:
            raise ValueError("Object SID unavailable")

        sid_raw = sid_values[0]
        if not isinstance(sid_raw, (bytes, bytearray)):
            raise ValueError("Object SID is in an unexpected format")
        return display, parse_sid(bytes(sid_raw))

    @staticmethod
    def _escape_search_term(term: str) -> str:
        return (
            term.replace("\\", r"\5c")
            .replace("*", r"\2a")
            .replace("(", r"\28")
            .replace(")", r"\29")
            .replace("\x00", "")
        )

    @staticmethod
    def _search_object_class_filter(search_mode: str) -> str:
        if search_mode == SEARCH_FILTER_COMPUTERS:
            return "(objectClass=computer)"
        if search_mode == SEARCH_FILTER_ORGANIZATIONAL_UNITS:
            return "(objectClass=organizationalUnit)"
        if search_mode == SEARCH_FILTER_GROUPS:
            return "(objectClass=group)"
        return "(|(objectClass=user)(objectClass=group))"

    def _build_search_filter(self, term: str, search_mode: str) -> str:
        safe_term = self._escape_search_term(term)
        class_filter = self._search_object_class_filter(search_mode)
        return (
            "(&"
            f"{class_filter}"
            "(|"
            f"(cn=*{safe_term}*)"
            f"(name=*{safe_term}*)"
            f"(sAMAccountName=*{safe_term}*)"
            f"(displayName=*{safe_term}*)"
            f"(description=*{safe_term}*)"
            ")"
            ")"
        )

    def search_objects(
        self,
        base_dn: str,
        term: str,
        search_mode: str = SEARCH_FILTER_USERS_CONTACTS_GROUPS,
        size_limit: int = 200,
    ) -> list[LdapObject]:
        if not self.conn:
            return []

        search_filter = self._build_search_filter(term, search_mode)

        entries = self._paged_search_entries(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "name", "cn", "objectClass", "description"],
            size_limit=size_limit,
        )
        results: list[LdapObject] = []
        for entry in entries:
            dn = str(entry.entry_dn)
            object_classes = [str(x).lower() for x in entry.objectClass.values] if "objectClass" in entry else []
            name = self._display_name(entry, object_classes, dn)
            description = ""
            if "description" in entry:
                try:
                    values = entry.description.values
                    if isinstance(values, list) and values:
                        description = str(values[0])
                    elif values:
                        description = str(values)
                except Exception:
                    description = ""

            results.append(
                LdapObject(
                    dn=dn,
                    name=name,
                    object_classes=object_classes,
                    description=description,
                )
            )

        results.sort(key=lambda x: (not x.is_container, x.name.lower()))
        self._populate_ou_child_status(results)
        return results

    def _populate_ou_child_status(self, objects: list[LdapObject]) -> None:
        if not self.conn:
            return

        for obj in objects:
            if "organizationalunit" not in obj.object_classes:
                continue

            try:
                self.conn.search(
                    search_base=obj.dn,
                    search_filter="(objectClass=organizationalUnit)",
                    search_scope=LEVEL,
                    attributes=["distinguishedName"],
                    size_limit=1,
                )
                obj.has_child_ou = bool(self.conn.entries)
            except Exception:
                obj.has_child_ou = False

    def get_single_attribute(self, dn: str, attr_name: str) -> Optional[str]:
        if not self.conn:
            return None

        self.conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=[attr_name],
        )
        if not self.conn.entries:
            return None

        entry = self.conn.entries[0]
        if attr_name not in entry:
            return None

        try:
            values = entry[attr_name].values
            if isinstance(values, list):
                return str(values[0]) if values else None
            return str(values)
        except Exception:
            return None

    @staticmethod
    def _is_user_disabled(entry, object_classes: list[str]) -> bool:
        if "user" not in object_classes or "computer" in object_classes:
            return False
        if "userAccountControl" not in entry:
            return False
        try:
            value = int(str(entry.userAccountControl))
        except Exception:
            return False
        return bool(value & 0x0002)

    @staticmethod
    def _is_user_locked(entry, object_classes: list[str]) -> bool:
        if "user" not in object_classes or "computer" in object_classes:
            return False
        if "lockoutTime" not in entry:
            return False
        try:
            value = int(str(entry.lockoutTime))
        except Exception:
            return False
        return value > 0

    @staticmethod
    def _is_computer_disabled(entry, object_classes: list[str]) -> bool:
        if "computer" not in object_classes:
            return False
        if "userAccountControl" not in entry:
            return False
        try:
            value = int(str(entry.userAccountControl))
        except Exception:
            return False
        return bool(value & 0x0002)

    def set_user_enabled(self, dn: str, enabled: bool) -> None:
        if not self.conn:
            return

        current_uac = self.get_single_attribute(dn, "userAccountControl")
        if current_uac is None:
            raise ValueError("Could not read userAccountControl")

        uac = int(current_uac)
        account_disable_bit = 0x0002

        if enabled:
            new_uac = uac & ~account_disable_bit
        else:
            new_uac = uac | account_disable_bit

        ok = self.conn.modify(
            dn,
            {"userAccountControl": [(MODIFY_REPLACE, [str(new_uac)])]},
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def set_user_account_control(self, dn: str, value: int) -> None:
        if not self.conn:
            return

        ok = self.conn.modify(
            dn,
            {"userAccountControl": [(MODIFY_REPLACE, [str(value)])]},
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def reset_password(self, dn: str, new_password: str) -> None:
        if not self.conn:
            return

        ok = self.conn.extend.microsoft.modify_password(dn, new_password)
        if not ok:
            raise ValueError(str(self.conn.result))

    def unlock_account(self, dn: str) -> None:
        if not self.conn:
            return

        ok = self.conn.modify(
            dn,
            {"lockoutTime": [(MODIFY_REPLACE, ["0"])]},
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def add_group_member(self, group_dn: str, member_dn: str) -> None:
        if not self.conn:
            return

        ok = self.conn.modify(
            group_dn,
            {"member": [(MODIFY_ADD, [member_dn])]},
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def remove_group_member(self, group_dn: str, member_dn: str) -> None:
        if not self.conn:
            return

        ok = self.conn.modify(
            group_dn,
            {"member": [(MODIFY_DELETE, [member_dn])]},
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def replace_object_attribute_values(self, dn: str, attr_name: str, values: list[str]) -> None:
        if not self.conn:
            return

        ok = self.conn.modify(
            dn,
            {attr_name: [(MODIFY_REPLACE, values)]},
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def get_object_summary(self, dn: str) -> Optional[LdapObject]:
        if not self.conn:
            return None

        self.conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=[
                "distinguishedName",
                "name",
                "cn",
                "objectClass",
                "description",
                "userAccountControl",
                "lockoutTime",
            ],
        )
        if not self.conn.entries:
            return None

        entry = self.conn.entries[0]
        object_classes = [str(x).lower() for x in entry.objectClass.values] if "objectClass" in entry else []
        name = self._display_name(entry, object_classes, dn)

        description = ""
        if "description" in entry:
            try:
                values = entry.description.values
                if isinstance(values, list) and values:
                    description = str(values[0])
                elif values:
                    description = str(values)
            except Exception:
                description = ""

        return LdapObject(
            dn=dn,
            name=name,
            object_classes=object_classes,
            description=description,
            user_disabled=self._is_user_disabled(entry, object_classes),
            user_locked=self._is_user_locked(entry, object_classes),
            computer_disabled=self._is_computer_disabled(entry, object_classes),
        )

    def get_group_members(self, group_dn: str) -> list[LdapObject]:
        if not self.conn:
            return []

        self.conn.search(
            search_base=group_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["member"],
        )
        if not self.conn.entries:
            return []

        entry = self.conn.entries[0]
        member_dns: list[str] = []
        if "member" in entry:
            try:
                member_dns = [str(v) for v in entry.member.values]
            except Exception:
                member_dns = []

        members: list[LdapObject] = []
        for member_dn in member_dns:
            obj = self.get_object_summary(member_dn)
            if obj is not None:
                members.append(obj)

        members.sort(key=lambda x: x.name.lower())
        return members

    def get_object_member_of(self, dn: str) -> list[LdapObject]:
        if not self.conn:
            return []

        self.conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["memberOf"],
        )
        if not self.conn.entries:
            return []

        entry = self.conn.entries[0]
        parent_dns: list[str] = []
        if "memberOf" in entry:
            try:
                parent_dns = [str(v) for v in entry.memberOf.values]
            except Exception:
                parent_dns = []

        groups: list[LdapObject] = []
        for parent_dn in parent_dns:
            obj = self.get_object_summary(parent_dn)
            if obj is not None:
                groups.append(obj)

        groups.sort(key=lambda x: x.name.lower())
        return groups

    def get_object_primary_group(self, dn: str) -> Optional[LdapObject]:
        if not self.conn:
            return None

        self.conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["primaryGroupID", "objectSid"],
        )
        if not self.conn.entries:
            return None

        entry = self.conn.entries[0]
        try:
            primary_group_id = str(entry.primaryGroupID.value)
            object_sid = str(entry.objectSid.value)
        except Exception:
            return None

        if not primary_group_id or not object_sid or "-" not in object_sid:
            return None

        domain_sid = object_sid.rsplit("-", 1)[0]
        primary_group_sid = f"{domain_sid}-{primary_group_id}"

        search_base = self.get_default_naming_context()
        if not search_base:
            return None

        self.conn.search(
            search_base=search_base,
            search_filter=f"(objectSid={primary_group_sid})",
            search_scope=SUBTREE,
            attributes=[
                "distinguishedName",
                "name",
                "cn",
                "objectClass",
                "description",
                "userAccountControl",
                "lockoutTime",
            ],
            size_limit=1,
        )
        if not self.conn.entries:
            return None

        group_entry = self.conn.entries[0]
        group_dn = str(group_entry.entry_dn)
        object_classes = [str(x).lower() for x in group_entry.objectClass.values] if "objectClass" in group_entry else []
        name = self._display_name(group_entry, object_classes, group_dn)
        description = ""
        if "description" in group_entry:
            try:
                values = group_entry.description.values
                if isinstance(values, list) and values:
                    description = str(values[0])
                elif values:
                    description = str(values)
            except Exception:
                description = ""

        return LdapObject(
            dn=group_dn,
            name=name,
            object_classes=object_classes,
            description=description,
            user_disabled=self._is_user_disabled(group_entry, object_classes),
            user_locked=self._is_user_locked(group_entry, object_classes),
            computer_disabled=self._is_computer_disabled(group_entry, object_classes),
        )

    def replace_group_members(self, group_dn: str, member_dns: list[str]) -> None:
        if not self.conn:
            return

        ok = self.conn.modify(
            group_dn,
            {"member": [(MODIFY_REPLACE, member_dns)]},
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def delete_object(self, dn: str) -> None:
        if not self.conn:
            return

        ok = self.conn.delete(dn)
        if not ok:
            raise ValueError(str(self.conn.result))

    def get_allowed_child_classes(self, dn: str) -> set[str]:
        if not self.conn:
            return set()

        self.conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["allowedChildClassesEffective", "allowedChildClasses"],
        )
        if not self.conn.entries:
            return set()

        entry = self.conn.entries[0]
        allowed_classes: set[str] = set()
        for attr in ("allowedChildClassesEffective", "allowedChildClasses"):
            if attr not in entry:
                continue
            try:
                values = entry[attr].values
                if isinstance(values, list):
                    allowed_classes.update(str(v).lower() for v in values)
                elif values:
                    allowed_classes.add(str(values).lower())
            except Exception:
                continue

        return allowed_classes

    def can_create_child_class(self, parent_dn: str, child_class: str) -> bool:
        if not self.conn:
            return False

        class_name = child_class.lower()
        probe_id = uuid.uuid4().hex
        rdn_attr = "OU" if class_name == "organizationalunit" else "CN"
        probe_dn = f"{rdn_attr}=__aduc_probe_{probe_id},{parent_dn}"

        ok = self.conn.add(
            probe_dn,
            attributes={
                "objectClass": ["top", class_name],
            },
        )
        if ok:
            self.conn.delete(probe_dn)
            return True

        result_code = int(self.conn.result.get("result", -1))
        if result_code == 50:
            return False

        return True

    def rename_object(self, dn: str, new_name: str) -> None:
        if not self.conn:
            return

        parts = [p.strip() for p in dn.split(",") if p.strip()]
        if not parts or "=" not in parts[0]:
            raise ValueError("Invalid distinguished name")

        rdn_type, _ = parts[0].split("=", 1)
        new_rdn = f"{rdn_type}={new_name}"
        ok = self.conn.modify_dn(dn, new_rdn)
        if not ok:
            raise ValueError(str(self.conn.result))

    @staticmethod
    def parent_dn(dn: str) -> Optional[str]:
        parts = [p.strip() for p in dn.split(",") if p.strip()]
        if len(parts) <= 1:
            return None
        return ",".join(parts[1:])

    def move_object(self, dn: str, target_parent_dn: str) -> None:
        if not self.conn:
            return

        parts = [p.strip() for p in dn.split(",") if p.strip()]
        if not parts or "=" not in parts[0]:
            raise ValueError("Invalid distinguished name")

        current_parent = self.parent_dn(dn)
        if current_parent and current_parent.lower() == target_parent_dn.lower():
            return

        rdn = parts[0]
        ok = self.conn.modify_dn(dn, rdn, new_superior=target_parent_dn)
        if not ok:
            raise ValueError(str(self.conn.result))

    def create_organizational_unit(self, parent_dn: str, name: str, description: str = "") -> str:
        if not self.conn:
            raise ValueError("Not connected")

        ou_dn = f"OU={name},{parent_dn}"
        attributes: dict[str, Any] = {"objectClass": ["top", "organizationalUnit"], "ou": name}
        if description:
            attributes["description"] = description

        ok = self.conn.add(ou_dn, attributes=attributes)
        if not ok:
            raise ValueError(str(self.conn.result))
        return ou_dn

    def create_group(
        self,
        parent_dn: str,
        name: str,
        sam_account_name: str,
        description: str = "",
        scope: str = "Global",
        security_enabled: bool = True,
    ) -> str:
        if not self.conn:
            raise ValueError("Not connected")

        group_dn = f"CN={name},{parent_dn}"
        scope_bits = {"Global": 0x00000002, "Domain Local": 0x00000004, "Universal": 0x00000008}
        group_type = scope_bits.get(scope, 0x00000002)
        if security_enabled:
            group_type |= 0x80000000
        if group_type > 0x7FFFFFFF:
            group_type -= 0x100000000

        attributes: dict[str, Any] = {
            "objectClass": ["top", "group"],
            "cn": name,
            "sAMAccountName": sam_account_name,
            "groupType": str(group_type),
        }
        if description:
            attributes["description"] = description

        ok = self.conn.add(group_dn, attributes=attributes)
        if not ok:
            raise ValueError(str(self.conn.result))
        return group_dn

    def create_user(
        self,
        parent_dn: str,
        name: str,
        sam_account_name: str,
        password: str = "",
        description: str = "",
        user_principal_name: str = "",
        enabled: bool = False,
    ) -> str:
        if not self.conn:
            raise ValueError("Not connected")

        user_dn = f"CN={name},{parent_dn}"
        attributes: dict[str, Any] = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": name,
            "sn": name,
            "displayName": name,
            "sAMAccountName": sam_account_name,
            "userAccountControl": "514",
        }
        if description:
            attributes["description"] = description
        if user_principal_name:
            attributes["userPrincipalName"] = user_principal_name

        ok = self.conn.add(user_dn, attributes=attributes)
        if not ok:
            raise ValueError(str(self.conn.result))

        if password:
            self.reset_password(user_dn, password)
            self.set_user_enabled(user_dn, enabled)

        return user_dn

    def create_computer(
        self,
        parent_dn: str,
        name: str,
        sam_account_name: str,
        description: str = "",
        enabled: bool = True,
    ) -> str:
        if not self.conn:
            raise ValueError("Not connected")

        computer_dn = f"CN={name},{parent_dn}"
        normalized_sam = sam_account_name if sam_account_name.endswith("$") else f"{sam_account_name}$"
        uac = 0x1000 if enabled else (0x1000 | 0x2)

        attributes: dict[str, Any] = {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "cn": name,
            "sAMAccountName": normalized_sam,
            "userAccountControl": str(uac),
        }
        if description:
            attributes["description"] = description

        ok = self.conn.add(computer_dn, attributes=attributes)
        if not ok:
            raise ValueError(str(self.conn.result))
        return computer_dn

    def search_directory_objects(
        self,
        base_dn: str,
        term: str,
        search_mode: str = SEARCH_FILTER_USERS_CONTACTS_GROUPS,
        size_limit: int = 200,
    ) -> list[LdapObject]:
        if not self.conn:
            return []

        search_filter = self._build_search_filter(term, search_mode)

        entries = self._paged_search_entries(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            # Needed for user icon overlays.
            attributes=[
                "distinguishedName",
                "name",
                "cn",
                "objectClass",
                "description",
                "userAccountControl",
                "lockoutTime",
            ],
            size_limit=size_limit,
        )
        results: list[LdapObject] = []
        for entry in entries:
            dn = str(entry.entry_dn)
            object_classes = [str(x).lower() for x in entry.objectClass.values] if "objectClass" in entry else []
            name = self._display_name(entry, object_classes, dn)

            description = ""
            if "description" in entry:
                try:
                    values = entry.description.values
                    if isinstance(values, list) and values:
                        description = str(values[0])
                    elif values:
                        description = str(values)
                except Exception:
                    description = ""

            results.append(
                LdapObject(
                    dn=dn,
                    name=name,
                    object_classes=object_classes,
                    description=description,
                    user_disabled=self._is_user_disabled(entry, object_classes),
                    user_locked=self._is_user_locked(entry, object_classes),
                    computer_disabled=self._is_computer_disabled(entry, object_classes),
                )
            )

        results.sort(key=lambda x: (x.object_type, x.name.lower()))
        return results


class ConnectDialog(QDialog):
    def __init__(
        self,
        auth_mode: str,
        saved_host: str = "",
        saved_port: int = 636,
        profiles: Optional[list[ConnectionProfile]] = None,
        selected_profile: str = "",
        auto_connect: bool = False,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Connect to Active Directory")
        self.auth_mode = auth_mode
        self.profiles = profiles or []

        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Manual (unsaved)", "")
        for profile in self.profiles:
            self.profile_combo.addItem(profile.name, profile.name)
        if selected_profile:
            index = self.profile_combo.findData(selected_profile)
            if index >= 0:
                self.profile_combo.setCurrentIndex(index)

        self.auth_mode_combo = QComboBox()
        self.auth_mode_combo.addItem("Credentials", "credentials")
        self.auth_mode_combo.addItem("Kerberos / SSO", "kerberos")
        idx = self.auth_mode_combo.findData(auth_mode)
        if idx >= 0:
            self.auth_mode_combo.setCurrentIndex(idx)

        self.auto_connect_combo = QComboBox()
        self.auto_connect_combo.addItem("Disabled", False)
        self.auto_connect_combo.addItem("Enabled", True)
        self.auto_connect_combo.setCurrentIndex(1 if auto_connect else 0)

        self.profile_name_edit = QLineEdit(selected_profile)
        self.save_profile_checkbox = QCheckBox("Save/update this connection profile")
        self.save_password_checkbox = QCheckBox("Save password in system keyring")
        self.delete_profile_btn = QPushButton("Delete saved profile")
        self.deleted_profile_names: set[str] = set()

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("dc01.example.com")
        if saved_host:
            self.host_edit.setText(saved_host)
        elif TEST_DC:
            self.host_edit.setText(TEST_DC)

        self.port_edit = QLineEdit(str(saved_port))

        self.bind_user_edit = QLineEdit()
        self.bind_user_edit.setPlaceholderText("admin@example.com or EXAMPLE\\admin")
        if TEST_BIND_USER:
            self.bind_user_edit.setText(TEST_BIND_USER)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        if TEST_BIND_PASSWORD:
            self.password_edit.setText(TEST_BIND_PASSWORD)

        form = QFormLayout()
        profile_row = QHBoxLayout()
        profile_row.addWidget(self.profile_combo, 1)
        profile_row.addWidget(self.delete_profile_btn)
        form.addRow("Profile:", profile_row)
        form.addRow("Profile name:", self.profile_name_edit)
        form.addRow("Authentication:", self.auth_mode_combo)
        form.addRow("Auto-connect on launch:", self.auto_connect_combo)
        form.addRow("Server:", self.host_edit)
        form.addRow("Port:", self.port_edit)
        form.addRow("Bind user:", self.bind_user_edit)
        form.addRow("Password:", self.password_edit)
        form.addRow("", self.save_profile_checkbox)
        form.addRow("", self.save_password_checkbox)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

        self.profile_combo.currentIndexChanged.connect(self.on_profile_selected)
        self.auth_mode_combo.currentIndexChanged.connect(self.update_auth_fields)
        self.save_profile_checkbox.toggled.connect(self.update_profile_controls)
        self.delete_profile_btn.clicked.connect(self.delete_selected_profile)
        self.update_auth_fields()
        self.update_profile_controls()
        self.on_profile_selected()

        # Make the connect dialog wide enough for long title bars and field contents.
        hint = self.sizeHint()
        self.setMinimumWidth(max(400, hint.width()))

    def values(self) -> tuple[str, int, str, str]:
        return (
            self.host_edit.text().strip(),
            int(self.port_edit.text().strip()),
            self.bind_user_edit.text().strip(),
            self.password_edit.text(),
        )

    def selected_auth_mode(self) -> str:
        return str(self.auth_mode_combo.currentData())

    def selected_auto_connect(self) -> bool:
        return bool(self.auto_connect_combo.currentData())

    def selected_profile_name(self) -> str:
        return self.profile_name_edit.text().strip()

    def deleted_profiles(self) -> list[str]:
        return sorted(self.deleted_profile_names)

    def save_profile_enabled(self) -> bool:
        return self.save_profile_checkbox.isChecked()

    def save_password_enabled(self) -> bool:
        return self.save_password_checkbox.isChecked() and self.selected_auth_mode() == "credentials"

    def on_profile_selected(self) -> None:
        selected = str(self.profile_combo.currentData() or "")
        if not selected:
            self.save_profile_checkbox.setChecked(False)
            self.save_password_checkbox.setChecked(False)
            self.update_profile_controls()
            return
        for profile in self.profiles:
            if profile.name != selected:
                continue
            self.profile_name_edit.setText(profile.name)
            self.host_edit.setText(profile.host)
            self.port_edit.setText(str(profile.port))
            self.bind_user_edit.setText(profile.bind_user)
            idx = self.auth_mode_combo.findData(profile.auth_mode)
            if idx >= 0:
                self.auth_mode_combo.setCurrentIndex(idx)
            self.save_profile_checkbox.setChecked(True)
            self.save_password_checkbox.setChecked(bool(profile.store_password))
            if profile.auth_mode == "credentials":
                if profile.store_password:
                    self.password_edit.setText(CredentialStore.get_password(profile.name))
                else:
                    self.password_edit.clear()
            self.update_profile_controls()
            break

    def update_auth_fields(self) -> None:
        kerberos = self.selected_auth_mode() == "kerberos"
        self.bind_user_edit.setEnabled(not kerberos)
        self.password_edit.setEnabled(not kerberos)
        self.save_password_checkbox.setEnabled(not kerberos and self.save_profile_checkbox.isChecked())
        if kerberos:
            self.bind_user_edit.setPlaceholderText("Using current Kerberos ticket")
            self.password_edit.setPlaceholderText("Using current Kerberos ticket")
        else:
            self.bind_user_edit.setPlaceholderText("admin@example.com or EXAMPLE\\admin")
            self.password_edit.setPlaceholderText("")

    def update_profile_controls(self) -> None:
        enabled = self.save_profile_checkbox.isChecked()
        self.profile_name_edit.setEnabled(enabled)
        self.save_password_checkbox.setEnabled(enabled and self.selected_auth_mode() == "credentials")

    def delete_selected_profile(self) -> None:
        selected = str(self.profile_combo.currentData() or "")
        if not selected:
            return
        if QMessageBox.question(
            self,
            "Delete saved profile",
            f"Delete saved profile '{selected}' and its stored password?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        ) != QMessageBox.Yes:
            return

        self.deleted_profile_names.add(selected)
        self.profiles = [profile for profile in self.profiles if profile.name != selected]

        idx = self.profile_combo.currentIndex()
        self.profile_combo.removeItem(idx)
        self.profile_combo.setCurrentIndex(0)


class OptionsDialog(QDialog):
    def __init__(self, auth_mode: str, auto_connect: bool, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Options")

        self.auth_mode_combo = QComboBox()
        self.auth_mode_combo.addItem("Credentials", "credentials")
        self.auth_mode_combo.addItem("Kerberos / SSO", "kerberos")
        if auth_mode == "kerberos":
            self.auth_mode_combo.setCurrentIndex(1)

        self.auto_connect_combo = QComboBox()
        self.auto_connect_combo.addItem("Disabled", False)
        self.auto_connect_combo.addItem("Enabled", True)
        self.auto_connect_combo.setCurrentIndex(1 if auto_connect else 0)

        idx = self.auth_mode_combo.findData(auth_mode)
        if idx >= 0:
            self.auth_mode_combo.setCurrentIndex(idx)

        self.auth_mode_combo.currentIndexChanged.connect(self.update_auto_connect_state)
        self.update_auto_connect_state()

        form = QFormLayout()
        form.addRow("Authentication:", self.auth_mode_combo)
        form.addRow("Auto-connect on launch:", self.auto_connect_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def selected_auth_mode(self) -> str:
        return str(self.auth_mode_combo.currentData())

    def selected_auto_connect(self) -> bool:
        return bool(self.auto_connect_combo.currentData())

    def update_auto_connect_state(self) -> None:
        # Auto-connect is supported for both credentials (when keyring credentials exist)
        # and Kerberos profiles.
        self.auto_connect_combo.setEnabled(True)


class SecurityAclEditor(QWidget):
    changed = Signal()

    PERMISSIONS: list[tuple[str, int]] = [
        ("Full Control", 0x10000000),
        ("Read", 0x80000000),
        ("Write", 0x40000000),
        ("Create All Child Objects", 0x00000001),
        ("Delete All Child Objects", 0x00000002),
        ("List Contents", 0x00000004),
        ("Read All Properties", 0x00000010),
        ("Write All Properties", 0x00000020),
        ("Delete", 0x00010000),
        ("Read Permissions", 0x00020000),
        ("Change Permissions", 0x00040000),
        ("Take Ownership", 0x00080000),
    ]
    MAPPED_PERMISSION_MASK = 0
    for _, _perm_mask in PERMISSIONS:
        MAPPED_PERMISSION_MASK |= _perm_mask
    FULL_CONTROL_INDEX = 0
    FULL_CONTROL_BIT = PERMISSIONS[FULL_CONTROL_INDEX][1]
    FULL_CONTROL_EXPANDED_MASK = 0
    for _idx, (_perm_name, _perm_mask) in enumerate(PERMISSIONS):
        if _idx == FULL_CONTROL_INDEX:
            continue
        FULL_CONTROL_EXPANDED_MASK |= _perm_mask
    # Common AD "Full Control" persisted mask for directory objects.
    FULL_CONTROL_AD_MASK = 0x000F01FF

    def __init__(self, ldap: LdapManager, object_dn: str, search_base: str, parent=None, show_apply_button: bool = True) -> None:
        super().__init__(parent)
        self.ldap = ldap
        self.object_dn = object_dn
        self.search_base = search_base
        self.owner_sid = ""
        self.group_sid = ""
        self.original_control = 0x8004
        self.principals: dict[str, dict[str, Any]] = {}
        self.display_by_sid: dict[str, str] = {}
        self._loading_permissions = False

        root = QVBoxLayout(self)

        top_label = QLabel("Group or user names:")
        root.addWidget(top_label)

        top_row = QHBoxLayout()
        self.principal_list = QListWidget()
        self.principal_list.setSelectionMode(QAbstractItemView.SingleSelection)
        top_row.addWidget(self.principal_list, 1)

        button_col = QVBoxLayout()
        self.add_btn = QPushButton("Add...")
        self.remove_btn = QPushButton("Remove")
        self.remove_btn.setEnabled(False)
        button_col.addWidget(self.add_btn)
        button_col.addWidget(self.remove_btn)
        button_col.addStretch(1)
        top_row.addLayout(button_col)
        root.addLayout(top_row, 1)

        self.permissions_label = QLabel("Permissions")
        root.addWidget(self.permissions_label)

        self.permissions_table = QTableWidget()
        self.permissions_table.setColumnCount(3)
        self.permissions_table.setHorizontalHeaderLabels(["Permission", "Allow", "Deny"])
        self.permissions_table.verticalHeader().setVisible(False)
        self.permissions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.permissions_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.permissions_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.permissions_table.setSelectionMode(QAbstractItemView.NoSelection)
        root.addWidget(self.permissions_table, 1)

        bottom_row = QHBoxLayout()
        self.meta_label = QLabel("")
        self.advanced_btn = QPushButton("Advanced")
        self.advanced_btn.setEnabled(False)
        self.apply_btn = QPushButton("Apply")
        self.apply_btn.setVisible(show_apply_button)
        bottom_row.addWidget(self.meta_label, 1)
        bottom_row.addWidget(self.advanced_btn)
        bottom_row.addWidget(self.apply_btn)
        root.addLayout(bottom_row)

        self.add_btn.clicked.connect(self.add_principal)
        self.remove_btn.clicked.connect(self.remove_selected_principal)
        self.principal_list.currentItemChanged.connect(self.on_principal_changed)
        self.permissions_table.itemChanged.connect(self.on_permission_item_changed)
        self.apply_btn.clicked.connect(self.apply_security_changes)

        self._build_permission_rows()
        self.reload_from_directory()

    def _build_permission_rows(self) -> None:
        self.special_row_index = len(self.PERMISSIONS)
        self.permissions_table.setRowCount(len(self.PERMISSIONS) + 1)
        for row, (perm_name, _mask) in enumerate(self.PERMISSIONS):
            perm_item = QTableWidgetItem(perm_name)
            perm_item.setFlags(Qt.ItemIsEnabled)
            self.permissions_table.setItem(row, 0, perm_item)
            for col in [1, 2]:
                box = QTableWidgetItem("")
                box.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)
                box.setCheckState(Qt.Unchecked)
                self.permissions_table.setItem(row, col, box)

        special_item = QTableWidgetItem("Special (unmapped)")
        special_item.setFlags(Qt.ItemIsEnabled)
        self.permissions_table.setItem(self.special_row_index, 0, special_item)
        for col in [1, 2]:
            box = QTableWidgetItem("")
            box.setFlags(Qt.ItemIsEnabled)
            box.setCheckState(Qt.Unchecked)
            self.permissions_table.setItem(self.special_row_index, col, box)
        self.permissions_table.setRowHidden(self.special_row_index, True)

    def reload_from_directory(self, select_sid: str = "") -> None:
        details = self.ldap.get_security_descriptor_details(self.object_dn)
        if details.get("error"):
            self.meta_label.setText(f"Unable to read security descriptor: {details.get('error')}")
            self.setEnabled(False)
            return

        self.setEnabled(True)
        self.owner_sid = str(details.get("owner_sid", ""))
        self.group_sid = str(details.get("group_sid", ""))
        self.original_control = int(details.get("control", 0x8004))
        self.principals = {}
        self.display_by_sid = {}

        for ace in details.get("dacl", []):
            sid = str(ace.get("trustee_sid", "")).strip()
            if not sid:
                continue
            entry = self.principals.setdefault(sid, {"allow": 0, "deny": 0})
            ace_type = int(ace.get("ace_type", -1))
            mask_value = int(ace.get("mask_value", 0))
            if ace_type in (0x00, 0x05):
                entry["allow"] |= mask_value
            elif ace_type in (0x01, 0x06):
                entry["deny"] |= mask_value

        self.principal_list.clear()
        for sid in sorted(self.principals.keys()):
            label = self.resolve_sid_label(sid)
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, sid)
            self.principal_list.addItem(item)

        if self.principal_list.count() > 0:
            target_sid = select_sid.strip()
            if target_sid and target_sid in self.principals:
                for row in range(self.principal_list.count()):
                    item = self.principal_list.item(row)
                    if item and str(item.data(Qt.UserRole)) == target_sid:
                        self.principal_list.setCurrentRow(row)
                        break
                else:
                    self.principal_list.setCurrentRow(0)
            else:
                self.principal_list.setCurrentRow(0)
        self.meta_label.setText("")
        self._original_principals = {sid: {"allow": int(v.get("allow", 0)), "deny": int(v.get("deny", 0))} for sid, v in self.principals.items()}

    def resolve_sid_label(self, sid: str) -> str:
        cached = self.display_by_sid.get(sid)
        if cached:
            return cached

        if sid in WELL_KNOWN_SID_LABELS:
            self.display_by_sid[sid] = WELL_KNOWN_SID_LABELS[sid]
            return WELL_KNOWN_SID_LABELS[sid]

        display_name = ""
        sam_name = ""
        netbios_hint = ""
        try:
            if self.ldap.conn:
                # AD-specific SID bind form resolves across partitions better than objectSid filters.
                self.ldap.conn.search(
                    search_base=f"<SID={sid}>",
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["displayName", "sAMAccountName", "cn", "name", "distinguishedName"],
                )
                if self.ldap.conn.entries:
                    entry = self.ldap.conn.entries[0]
                    for attr in ["displayName", "cn", "name"]:
                        values = self.ldap._entry_attr_values(entry, attr)
                        if values:
                            display_name = values[0]
                            break
                    sam_values = self.ldap._entry_attr_values(entry, "sAMAccountName")
                    if sam_values:
                        sam_name = sam_values[0]

                    dn_values = self.ldap._entry_attr_values(entry, "distinguishedName")
                    if dn_values:
                        dn = dn_values[0]
                        dc_parts = [part[3:] for part in dn.split(",") if part.upper().startswith("DC=")]
                        if dc_parts:
                            netbios_hint = dc_parts[0].upper()
        except Exception:
            pass

        if not display_name and sam_name:
            display_name = sam_name
        if sam_name and netbios_hint:
            qualifier = f"{netbios_hint}\\{sam_name}"
        elif sam_name:
            qualifier = sam_name
        else:
            qualifier = ""

        if not display_name and qualifier:
            display_name = qualifier

        if not display_name:
            rendered = sid
        elif qualifier and display_name != qualifier:
            rendered = f"{display_name} ({qualifier})"
        else:
            rendered = display_name

        self.display_by_sid[sid] = rendered
        return rendered

    def on_principal_changed(self, current: Optional[QListWidgetItem], previous: Optional[QListWidgetItem]) -> None:
        if previous is not None and not self._loading_permissions:
            previous_sid = str(previous.data(Qt.UserRole))
            self._capture_permission_checkboxes_for_sid(previous_sid)

        self.remove_btn.setEnabled(current is not None)
        if current is None:
            self.permissions_label.setText("Permissions")
            self._loading_permissions = True
            for row in range(self.permissions_table.rowCount()):
                self.permissions_table.item(row, 1).setCheckState(Qt.Unchecked)
                self.permissions_table.item(row, 2).setCheckState(Qt.Unchecked)
            self.permissions_table.setRowHidden(self.special_row_index, True)
            self._loading_permissions = False
            return

        sid = str(current.data(Qt.UserRole))
        data = self.principals.get(sid, {"allow": 0, "deny": 0})
        self.permissions_label.setText(f"Permissions for {current.text().split(' (')[0]}")
        allow_mask = int(data.get("allow", 0))
        deny_mask = int(data.get("deny", 0))
        allow_unmapped = allow_mask & ~self.MAPPED_PERMISSION_MASK
        deny_unmapped = deny_mask & ~self.MAPPED_PERMISSION_MASK
        allow_full_control = bool(
            (allow_mask & self.FULL_CONTROL_BIT)
            or ((allow_mask & self.FULL_CONTROL_EXPANDED_MASK) == self.FULL_CONTROL_EXPANDED_MASK)
            or ((allow_mask & self.FULL_CONTROL_AD_MASK) == self.FULL_CONTROL_AD_MASK)
        )
        deny_full_control = bool(
            (deny_mask & self.FULL_CONTROL_BIT)
            or ((deny_mask & self.FULL_CONTROL_EXPANDED_MASK) == self.FULL_CONTROL_EXPANDED_MASK)
            or ((deny_mask & self.FULL_CONTROL_AD_MASK) == self.FULL_CONTROL_AD_MASK)
        )
        self._loading_permissions = True
        for row, (_perm_name, bit) in enumerate(self.PERMISSIONS):
            if row == self.FULL_CONTROL_INDEX:
                self.permissions_table.item(row, 1).setCheckState(Qt.Checked if allow_full_control else Qt.Unchecked)
                self.permissions_table.item(row, 2).setCheckState(Qt.Checked if deny_full_control else Qt.Unchecked)
                continue
            self.permissions_table.item(row, 1).setCheckState(Qt.Checked if (allow_mask & bit) else Qt.Unchecked)
            self.permissions_table.item(row, 2).setCheckState(Qt.Checked if (deny_mask & bit) else Qt.Unchecked)
        has_unmapped = bool(allow_unmapped or deny_unmapped)
        self.permissions_table.setRowHidden(self.special_row_index, not has_unmapped)
        self.permissions_table.item(self.special_row_index, 1).setCheckState(Qt.Checked if allow_unmapped else Qt.Unchecked)
        self.permissions_table.item(self.special_row_index, 2).setCheckState(Qt.Checked if deny_unmapped else Qt.Unchecked)
        self._loading_permissions = False

    def on_permission_item_changed(self, item: QTableWidgetItem) -> None:
        if self._loading_permissions:
            return

        row = item.row()
        col = item.column()
        if col in (1, 2):
            self._loading_permissions = True
            try:
                if row == self.FULL_CONTROL_INDEX:
                    state = item.checkState()
                    for perm_row in range(len(self.PERMISSIONS)):
                        perm_item = self.permissions_table.item(perm_row, col)
                        if perm_item is not None:
                            perm_item.setCheckState(state)
                else:
                    all_checked = True
                    for perm_row in range(1, len(self.PERMISSIONS)):
                        perm_item = self.permissions_table.item(perm_row, col)
                        if perm_item is None or perm_item.checkState() != Qt.Checked:
                            all_checked = False
                            break
                    full_control_item = self.permissions_table.item(self.FULL_CONTROL_INDEX, col)
                    if full_control_item is not None:
                        full_control_item.setCheckState(Qt.Checked if all_checked else Qt.Unchecked)
            finally:
                self._loading_permissions = False

        self._capture_permission_checkboxes()
        self.changed.emit()

    def add_principal(self) -> None:
        principal_search_base = self.ldap.get_default_naming_context() or self.search_base
        dlg = SelectDirectoryObjectsDialog(
            self.ldap,
            principal_search_base,
            self,
            search_options=[("Users and Groups", SEARCH_FILTER_USERS_CONTACTS_GROUPS)],
        )
        if dlg.exec() != QDialog.Accepted:
            return
        selected = dlg.selected_objects()
        if not selected:
            return
        obj = selected[0]
        try:
            display, sid = self.ldap.get_object_display_and_sid(obj.dn)
        except Exception as e:
            QMessageBox.critical(self, "Add principal failed", str(e))
            return

        if sid not in self.principals:
            self.principals[sid] = {"allow": 0, "deny": 0}
        self.display_by_sid[sid] = f"{display} ({sid})"
        self.refresh_principal_list(select_sid=sid)
        self.changed.emit()

    def remove_selected_principal(self) -> None:
        item = self.principal_list.currentItem()
        if not item:
            return
        sid = str(item.data(Qt.UserRole))
        if sid in self.principals:
            del self.principals[sid]
        self.refresh_principal_list()
        self.changed.emit()

    def refresh_principal_list(self, select_sid: str = "") -> None:
        self.principal_list.clear()
        target_row = -1
        for row, sid in enumerate(sorted(self.principals.keys())):
            label = self.resolve_sid_label(sid)
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, sid)
            self.principal_list.addItem(item)
            if sid == select_sid:
                target_row = row
        if target_row >= 0:
            self.principal_list.setCurrentRow(target_row)
        elif self.principal_list.count() > 0:
            self.principal_list.setCurrentRow(0)

    def _build_dacl_bytes(self) -> bytes:
        ace_payloads: list[bytes] = []
        for sid in sorted(self.principals.keys()):
            data = self.principals[sid]
            sid_bytes = sid_to_bytes(sid)
            allow_mask = int(data.get("allow", 0))
            deny_mask = int(data.get("deny", 0))

            ace_flags = CREATOR_INHERIT_ACE_FLAGS if sid in CREATOR_SIDS else 0x00
            if deny_mask:
                ace_size = 8 + len(sid_bytes)
                ace_payloads.append(bytes([0x01, ace_flags]) + struct.pack("<H", ace_size) + struct.pack("<I", deny_mask) + sid_bytes)
            if allow_mask:
                ace_size = 8 + len(sid_bytes)
                ace_payloads.append(bytes([0x00, ace_flags]) + struct.pack("<H", ace_size) + struct.pack("<I", allow_mask) + sid_bytes)

        acl_size = 8 + sum(len(ace) for ace in ace_payloads)
        header = struct.pack("<BBHHH", 0x02, 0x00, acl_size, len(ace_payloads), 0x0000)
        return header + b"".join(ace_payloads)

    def _build_security_descriptor(self) -> bytes:
        owner_bytes = sid_to_bytes(self.owner_sid) if self.owner_sid else b""
        group_bytes = sid_to_bytes(self.group_sid) if self.group_sid else b""
        dacl_bytes = self._build_dacl_bytes()

        offset = 20
        owner_off = offset if owner_bytes else 0
        offset += len(owner_bytes)
        group_off = offset if group_bytes else 0
        offset += len(group_bytes)
        dacl_off = offset if dacl_bytes else 0

        control = (self.original_control | 0x8000 | 0x0004)
        header = struct.pack("<BBHLLLL", 1, 0, control, owner_off, group_off, 0, dacl_off)
        return header + owner_bytes + group_bytes + dacl_bytes

    def _capture_permission_checkboxes(self) -> None:
        item = self.principal_list.currentItem()
        if not item:
            return
        sid = str(item.data(Qt.UserRole))
        self._capture_permission_checkboxes_for_sid(sid)

    def _capture_permission_checkboxes_for_sid(self, sid: str) -> None:
        allow_mask = 0
        deny_mask = 0
        allow_full_control_checked = self.permissions_table.item(self.FULL_CONTROL_INDEX, 1).checkState() == Qt.Checked
        deny_full_control_checked = self.permissions_table.item(self.FULL_CONTROL_INDEX, 2).checkState() == Qt.Checked

        for row, (_perm_name, bit) in enumerate(self.PERMISSIONS):
            if row == self.FULL_CONTROL_INDEX:
                continue
            if self.permissions_table.item(row, 1).checkState() == Qt.Checked:
                allow_mask |= bit
            if self.permissions_table.item(row, 2).checkState() == Qt.Checked:
                deny_mask |= bit

        if allow_full_control_checked:
            allow_mask |= self.FULL_CONTROL_BIT | self.FULL_CONTROL_EXPANDED_MASK | self.FULL_CONTROL_AD_MASK
        if deny_full_control_checked:
            deny_mask |= self.FULL_CONTROL_BIT | self.FULL_CONTROL_EXPANDED_MASK | self.FULL_CONTROL_AD_MASK

        existing = self.principals.get(sid, {"allow": 0, "deny": 0})
        allow_unmapped = int(existing.get("allow", 0)) & ~self.MAPPED_PERMISSION_MASK
        deny_unmapped = int(existing.get("deny", 0)) & ~self.MAPPED_PERMISSION_MASK
        self.principals[sid] = {
            "allow": allow_mask | allow_unmapped,
            "deny": deny_mask | deny_unmapped,
        }

    def has_pending_changes(self) -> bool:
        self._capture_permission_checkboxes()
        if not hasattr(self, "_original_principals"):
            return False
        return self.principals != self._original_principals

    def apply_security_changes(self, reload_after_save: bool = True) -> bool:
        self._capture_permission_checkboxes()
        current_item = self.principal_list.currentItem()
        selected_sid = str(current_item.data(Qt.UserRole)) if current_item else ""

        try:
            with busy_cursor():
                sd = self._build_security_descriptor()
                self.ldap.set_security_descriptor(self.object_dn, sd)
                if reload_after_save:
                    self.reload_from_directory(select_sid=selected_sid)
        except Exception as e:
            QMessageBox.critical(self, "Apply security failed", str(e))
            return False

        if not reload_after_save:
            self._original_principals = {sid: {"allow": int(v.get("allow", 0)), "deny": int(v.get("deny", 0))} for sid, v in self.principals.items()}
            self.changed.emit()
        return True


def build_acl_viewer_tab(ldap: LdapManager, object_dn: str, search_base: str, show_apply_button: bool = True) -> QWidget:
    return SecurityAclEditor(ldap, object_dn, search_base, show_apply_button=show_apply_button)


class PropertiesDialog(QDialog):
    def __init__(
        self,
        ldap: LdapManager,
        obj: LdapObject,
        attrs: dict[str, list[str]],
        search_base: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(obj.name)
        self.resize(800, 600)

        tabs = QTabWidget()

        general = QWidget()
        general_layout = QFormLayout(general)

        general_layout.addRow("Name:", QLabel(obj.name))
        general_layout.addRow("Type:", QLabel(obj.object_type))
        general_layout.addRow("DN:", QLabel(obj.dn))
        general_layout.addRow("Description:", QLabel(obj.description or ""))

        tabs.addTab(general, "General")

        attributes_tab = QWidget()
        attributes_layout = QVBoxLayout(attributes_tab)

        text = QTextEdit()
        text.setReadOnly(True)

        lines: list[str] = []
        for key, values in attrs.items():
            lines.append(f"{key}:")
            for v in values:
                lines.append(f"  {v}")
            lines.append("")

        text.setPlainText("\n".join(lines))
        attributes_layout.addWidget(text)

        tabs.addTab(attributes_tab, "Attributes")
        tabs.addTab(build_acl_viewer_tab(ldap, obj.dn, search_base), "Security")

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)


class SingleValueAttributeEditorDialog(QDialog):
    def __init__(self, title: str, value: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(500, 140)

        layout = QVBoxLayout(self)
        self.value_edit = QLineEdit()
        self.value_edit.setText(value)
        layout.addWidget(self.value_edit)

        button_row = QHBoxLayout()
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.value_edit.clear)
        button_row.addWidget(self.clear_btn)
        button_row.addStretch()
        layout.addLayout(button_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def edited_value(self) -> str:
        return self.value_edit.text().strip()


class MultiValuedStringEditorDialog(QDialog):
    def __init__(self, attr_name: str, values: list[str], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Multi-Valued String Editor")
        self.resize(560, 420)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Attribute:  {attr_name}"))

        add_label = QLabel("Value to add:")
        layout.addWidget(add_label)

        add_row = QHBoxLayout()
        self.add_value_edit = QLineEdit()
        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self.add_value)
        add_row.addWidget(self.add_value_edit)
        add_row.addWidget(self.add_btn)
        layout.addLayout(add_row)

        layout.addWidget(QLabel("Values:"))
        values_row = QHBoxLayout()
        self.values_list = QListWidget()
        self.values_list.addItems(values)
        self.values_list.itemSelectionChanged.connect(self.refresh_remove_button_state)
        self.remove_btn = QPushButton("Remove")
        self.remove_btn.clicked.connect(self.remove_selected_value)
        values_row.addWidget(self.values_list, 1)
        values_row.addWidget(self.remove_btn, 0, Qt.AlignTop)
        layout.addLayout(values_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.refresh_remove_button_state()

    def add_value(self) -> None:
        value = self.add_value_edit.text().strip()
        if not value:
            return
        existing = [self.values_list.item(i).text() for i in range(self.values_list.count())]
        if value in existing:
            self.add_value_edit.clear()
            return
        self.values_list.addItem(value)
        self.add_value_edit.clear()

    def refresh_remove_button_state(self) -> None:
        self.remove_btn.setEnabled(bool(self.values_list.selectedItems()))

    def remove_selected_value(self) -> None:
        for item in self.values_list.selectedItems():
            self.values_list.takeItem(self.values_list.row(item))
        self.refresh_remove_button_state()

    def edited_values(self) -> list[str]:
        values = [self.values_list.item(i).text().strip() for i in range(self.values_list.count())]
        return [v for v in values if v]


class ComputerPropertiesDialog(QDialog):
    PRIMARY_GROUP_ID_TO_DC_TYPE = {
        "515": "Computer",
        "516": "Domain Controller",
        "521": "Read-only Domain Controller",
    }

    NON_EDITABLE_ATTRIBUTES = {
        "distinguishedName",
        "objectClass",
        "objectGUID",
        "objectSid",
        "whenCreated",
        "whenChanged",
        "uSNCreated",
        "uSNChanged",
        "memberOf",
        "member",
    }

    def __init__(
        self,
        ldap: LdapManager,
        obj: LdapObject,
        attrs: dict[str, list[str]],
        search_base: str,
        show_empty_attributes: bool = False,
        on_toggle_show_empty_attributes=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(obj.name)
        self.resize(920, 650)
        self.ldap = ldap
        self.computer_obj = obj
        self.search_base = search_base
        self.original_group_dns: list[str] = sorted(attrs.get("memberOf", []), key=str.lower)
        self.primary_group_dn: Optional[str] = None
        self.original_description = self._single_attr(attrs, "description")
        self.original_location = self._single_attr(attrs, "location")
        self.original_managed_by = self._single_attr(attrs, "managedBy")

        uac_raw = self._single_attr(attrs, "userAccountControl")
        try:
            self.current_uac_value = int(uac_raw) if uac_raw else 0
        except ValueError:
            self.current_uac_value = 0
        self.original_delegation_mode = "none"
        self.original_protocol_any_auth = False
        self.original_delegation_services = sorted(attrs.get("msDS-AllowedToDelegateTo", []), key=str.lower)

        self.attribute_values: dict[str, list[str]] = {k: [str(v) for v in vals] for k, vals in attrs.items()}
        self.original_attribute_values: dict[str, list[str]] = {k: list(v) for k, v in self.attribute_values.items()}
        self.selected_attribute: Optional[str] = None
        self.attribute_name_label: Optional[QLabel] = None
        self.attribute_value_edit: Optional[QTextEdit] = None
        self.show_empty_attributes = bool(show_empty_attributes)
        self.on_toggle_show_empty_attributes = on_toggle_show_empty_attributes

        self.apply_button: Optional[QPushButton] = None

        tabs = QTabWidget()
        tabs.addTab(self.build_general_tab(obj, attrs), "General")
        tabs.addTab(self.build_operating_system_tab(attrs), "Operating System")
        tabs.addTab(self.build_member_of_tab(attrs), "Member Of")
        tabs.addTab(self.build_delegation_tab(attrs), "Delegation")
        tabs.addTab(self.build_laps_tab(attrs), "LAPS")
        tabs.addTab(self.build_location_tab(attrs), "Location")
        tabs.addTab(self.build_managed_by_tab(attrs), "Managed By")
        tabs.addTab(self.build_attributes_tab(attrs), "Attributes")
        self.security_editor = build_acl_viewer_tab(self.ldap, obj.dn, self.search_base, show_apply_button=False)
        self.security_editor.changed.connect(self.refresh_apply_button_state)
        tabs.addTab(self.security_editor, "Security")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.Apply)
        buttons.accepted.connect(self.on_ok)
        buttons.rejected.connect(self.reject)
        apply_button = buttons.button(QDialogButtonBox.Apply)
        if apply_button:
            self.apply_button = apply_button
            apply_button.clicked.connect(self.apply_changes)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)
        self.refresh_apply_button_state()

    def _single_attr(self, attrs: dict[str, list[str]], attr: str) -> str:
        values = attrs.get(attr, [])
        return values[0] if values else ""

    def _readonly_line(self, value: str) -> QLineEdit:
        edit = QLineEdit(value)
        edit.setReadOnly(True)
        return edit

    def _dc_type_display_value(self, attrs: dict[str, list[str]]) -> str:
        primary_group_id = self._single_attr(attrs, "primaryGroupID")
        if not primary_group_id:
            return "Computer"

        return self.PRIMARY_GROUP_ID_TO_DC_TYPE.get(primary_group_id, f"Unknown ({primary_group_id})")

    def build_general_tab(self, obj: LdapObject, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_row = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(icon_for_directory_object(self.style(), obj).pixmap(32, 32))
        header_row.addWidget(icon_label, 0, Qt.AlignTop)

        name_label = QLabel(obj.name)
        font = name_label.font()
        font.setBold(True)
        font.setPointSize(max(font.pointSize(), 11))
        name_label.setFont(font)
        header_row.addWidget(name_label)
        header_row.addStretch()
        layout.addLayout(header_row)

        form = QFormLayout()
        self.dns_name_edit = self._readonly_line(self._single_attr(attrs, "dNSHostName") or obj.name)
        self.dc_type_edit = self._readonly_line(self._dc_type_display_value(attrs))
        self.site_edit = self._readonly_line(self._single_attr(attrs, "msDS-SiteName"))
        self.description_edit = QLineEdit(self.original_description)
        self.description_edit.textChanged.connect(self.refresh_apply_button_state)

        form.addRow("DNS Name:", self.dns_name_edit)
        form.addRow("DC Type:", self.dc_type_edit)
        form.addRow("Site:", self.site_edit)
        form.addRow("Description:", self.description_edit)
        form.addRow("DN:", self._readonly_line(obj.dn))

        layout.addLayout(form)
        layout.addStretch()
        return tab

    def build_operating_system_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.addRow("Name:", self._readonly_line(self._single_attr(attrs, "operatingSystem")))
        form.addRow("Version:", self._readonly_line(self._single_attr(attrs, "operatingSystemVersion")))
        form.addRow("Service pack:", self._readonly_line(self._single_attr(attrs, "operatingSystemServicePack")))
        return tab

    def build_member_of_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.member_of_table = QTableWidget()
        self.member_of_table.setColumnCount(2)
        self.member_of_table.setHorizontalHeaderLabels(["Name", "Distinguished Name"])
        self.member_of_table.verticalHeader().setVisible(False)
        self.member_of_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.member_of_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.member_of_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.member_of_table.itemSelectionChanged.connect(self.refresh_member_of_remove_button_state)

        groups = list(attrs.get("memberOf", []))
        primary_group = self.ldap.get_object_primary_group(self.computer_obj.dn)
        if primary_group is not None:
            self.primary_group_dn = primary_group.dn
            if primary_group.dn not in groups:
                groups.append(primary_group.dn)

        self.member_of_table.setRowCount(len(groups))
        for row, dn in enumerate(sorted(groups, key=str.lower)):
            short_name = dn.split(",", 1)[0].split("=", 1)[-1] if "=" in dn else dn
            name_item = QTableWidgetItem(short_name)
            dn_item = QTableWidgetItem(dn)
            is_primary = bool(self.primary_group_dn and dn.lower() == self.primary_group_dn.lower())
            dn_item.setData(Qt.UserRole, is_primary)
            if is_primary:
                name_item.setToolTip("Primary group")
                dn_item.setToolTip("Primary group")
            self.member_of_table.setItem(row, 0, name_item)
            self.member_of_table.setItem(row, 1, dn_item)

        button_row = QHBoxLayout()
        self.member_of_add_btn = QPushButton("Add...")
        self.member_of_remove_btn = QPushButton("Remove")
        button_row.addWidget(self.member_of_add_btn)
        button_row.addWidget(self.member_of_remove_btn)
        button_row.addStretch()

        self.member_of_add_btn.clicked.connect(self.add_group_memberships)
        self.member_of_remove_btn.clicked.connect(self.remove_selected_group_memberships)

        self.member_of_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.member_of_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)

        layout.addWidget(self.member_of_table)
        layout.addLayout(button_row)
        self.refresh_member_of_remove_button_state()
        return tab

    def _parse_delegation_service(self, service_name: str) -> tuple[str, str, str, str]:
        value = service_name.strip()
        if not value:
            return "", "", "", ""

        service_type = value
        target = ""
        port = ""
        if "/" in value:
            service_type, remainder = value.split("/", 1)
            target = remainder
        else:
            remainder = value

        if ":" in remainder:
            target_name, maybe_port = remainder.rsplit(":", 1)
            if maybe_port.isdigit():
                target = target_name
                port = maybe_port

        return service_type, target, port, value

    def _delegation_services_from_table(self) -> list[str]:
        services: list[str] = []
        for row in range(self.delegation_services_table.rowCount()):
            full_item = self.delegation_services_table.item(row, 3)
            full_value = full_item.text().strip() if full_item else ""
            if full_value:
                services.append(full_value)
        return sorted(set(services), key=str.lower)

    def build_delegation_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(
            QLabel(
                "Delegation is a security-sensitive operation, which allows services to act on behalf of another user."
            )
        )

        self.delegate_none_radio = QRadioButton("Do not trust this computer for delegation")
        self.delegate_any_radio = QRadioButton("Trust this computer for delegation to any service (Kerberos only)")
        self.delegate_specified_radio = QRadioButton("Trust this computer for delegation to specified services only")

        self.delegation_mode_group = QButtonGroup(self)
        self.delegation_mode_group.setExclusive(True)
        self.delegation_mode_group.addButton(self.delegate_none_radio)
        self.delegation_mode_group.addButton(self.delegate_any_radio)
        self.delegation_mode_group.addButton(self.delegate_specified_radio)

        self.delegate_none_radio.toggled.connect(self.refresh_delegation_controls)
        self.delegate_any_radio.toggled.connect(self.refresh_delegation_controls)
        self.delegate_specified_radio.toggled.connect(self.refresh_delegation_controls)

        layout.addWidget(self.delegate_none_radio)
        layout.addWidget(self.delegate_any_radio)
        layout.addWidget(self.delegate_specified_radio)

        protocol_widget = QWidget()
        protocol_layout = QVBoxLayout(protocol_widget)
        protocol_layout.setContentsMargins(24, 0, 0, 0)
        self.delegate_kerberos_only_radio = QRadioButton("Use Kerberos only")
        self.delegate_any_auth_radio = QRadioButton("Use any authentication protocol")
        self.delegation_protocol_group = QButtonGroup(self)
        self.delegation_protocol_group.setExclusive(True)
        self.delegation_protocol_group.addButton(self.delegate_kerberos_only_radio)
        self.delegation_protocol_group.addButton(self.delegate_any_auth_radio)
        self.delegate_kerberos_only_radio.toggled.connect(self.refresh_apply_button_state)
        self.delegate_any_auth_radio.toggled.connect(self.refresh_apply_button_state)
        protocol_layout.addWidget(self.delegate_kerberos_only_radio)
        protocol_layout.addWidget(self.delegate_any_auth_radio)
        layout.addWidget(protocol_widget)

        layout.addWidget(QLabel("Services to which this account can present delegated credentials:"))

        self.delegation_services_table = QTableWidget()
        self.delegation_services_table.setColumnCount(4)
        self.delegation_services_table.setHorizontalHeaderLabels(
            ["Service Type", "User or Computer", "Port", "Service Name"]
        )
        self.delegation_services_table.verticalHeader().setVisible(False)
        self.delegation_services_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.delegation_services_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.delegation_services_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.delegation_services_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.delegation_services_table.itemSelectionChanged.connect(self.refresh_delegation_controls)
        layout.addWidget(self.delegation_services_table)

        service_button_row = QHBoxLayout()
        self.delegation_expanded_checkbox = QCheckBox("Expanded")
        self.delegation_add_btn = QPushButton("Add")
        self.delegation_remove_btn = QPushButton("Remove")
        self.delegation_add_btn.clicked.connect(self.add_delegation_service)
        self.delegation_remove_btn.clicked.connect(self.remove_selected_delegation_services)
        service_button_row.addWidget(self.delegation_expanded_checkbox)
        service_button_row.addStretch()
        service_button_row.addWidget(self.delegation_add_btn)
        service_button_row.addWidget(self.delegation_remove_btn)
        layout.addLayout(service_button_row)

        services = sorted(attrs.get("msDS-AllowedToDelegateTo", []), key=str.lower)
        self.delegation_services_table.setRowCount(len(services))
        for row, service_name in enumerate(services):
            service_type, target, port, full_value = self._parse_delegation_service(service_name)
            self.delegation_services_table.setItem(row, 0, QTableWidgetItem(service_type))
            self.delegation_services_table.setItem(row, 1, QTableWidgetItem(target))
            self.delegation_services_table.setItem(row, 2, QTableWidgetItem(port))
            self.delegation_services_table.setItem(row, 3, QTableWidgetItem(full_value))

        trusted_for_delegation = bool(self.current_uac_value & 0x80000)
        trusted_to_auth = bool(self.current_uac_value & 0x1000000)

        if trusted_for_delegation:
            self.original_delegation_mode = "any"
            self.delegate_any_radio.setChecked(True)
        elif services:
            self.original_delegation_mode = "specified"
            self.delegate_specified_radio.setChecked(True)
        else:
            self.original_delegation_mode = "none"
            self.delegate_none_radio.setChecked(True)

        self.original_protocol_any_auth = trusted_to_auth
        if trusted_to_auth:
            self.delegate_any_auth_radio.setChecked(True)
        else:
            self.delegate_kerberos_only_radio.setChecked(True)

        layout.addStretch()
        self.refresh_delegation_controls()
        return tab

    def build_laps_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        title = QLabel("Local Administrator Password Solution")
        title_font = title.font()
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        form = QFormLayout()
        self.laps_expiry_edit = self._readonly_line(self._single_attr(attrs, "msLAPS-PasswordExpirationTime"))
        form.addRow("Current LAPS password expiration:", self.laps_expiry_edit)

        expiry_row = QHBoxLayout()
        self.laps_new_expiry_picker = QDateTimeEdit(QDateTime.currentDateTime())
        self.laps_new_expiry_picker.setCalendarPopup(True)
        laps_calendar = self.laps_new_expiry_picker.calendarWidget()
        laps_calendar.setFirstDayOfWeek(Qt.Sunday)
        laps_calendar.clicked.connect(self._on_laps_calendar_date_selected)
        self.laps_new_expiry_picker.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.laps_expire_now_btn = QPushButton("Expire Now")
        expiry_row.addWidget(self.laps_new_expiry_picker)
        expiry_row.addWidget(self.laps_expire_now_btn)

        expiry_container = QWidget()
        expiry_container.setLayout(expiry_row)
        form.addRow("Set new LAPS password expiration:", expiry_container)

        form.addRow("LAPS local admin account name:", self._readonly_line(self._single_attr(attrs, "msLAPS-LocalAdminAccountName")))

        self.laps_password_edit = self._readonly_line(self._single_attr(attrs, "msLAPS-Password"))
        form.addRow("LAPS local admin account password:", self.laps_password_edit)

        layout.addLayout(form)

        button_row = QHBoxLayout()
        self.laps_copy_password_btn = QPushButton("Copy Password")
        self.laps_show_password_btn = QPushButton("Show Password")
        has_password = bool(self.laps_password_edit.text().strip())
        self.laps_copy_password_btn.setEnabled(has_password)
        self.laps_show_password_btn.setEnabled(has_password)
        button_row.addStretch()
        button_row.addWidget(self.laps_copy_password_btn)
        button_row.addWidget(self.laps_show_password_btn)
        layout.addLayout(button_row)

        layout.addStretch()
        return tab

    def _on_laps_calendar_date_selected(self, *_args: object) -> None:
        selected_datetime = self.laps_new_expiry_picker.dateTime()

        dialog = QDialog(self)
        dialog.setWindowTitle("Select Expiration Time")
        dialog_layout = QVBoxLayout(dialog)
        dialog_layout.addWidget(QLabel("Select time for the chosen date:"))

        time_edit = QTimeEdit(selected_datetime.time())
        time_edit.setDisplayFormat("HH:mm:ss")
        dialog_layout.addWidget(time_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        dialog_layout.addWidget(buttons)

        if dialog.exec() != QDialog.Accepted:
            return

        selected_datetime.setTime(time_edit.time())
        self.laps_new_expiry_picker.setDateTime(selected_datetime)

    def build_location_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        self.location_edit = QLineEdit(self.original_location)
        self.location_edit.textChanged.connect(self.refresh_apply_button_state)
        form.addRow("Location:", self.location_edit)
        return tab

    def build_managed_by_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)

        name_row = QHBoxLayout()
        self.managed_by_name_edit = QLineEdit(self.original_managed_by)
        self.managed_by_name_edit.textChanged.connect(self._on_managed_by_changed)
        self.managed_by_change_btn = QPushButton("Change")
        self.managed_by_properties_btn = QPushButton("Properties")
        self.managed_by_clear_btn = QPushButton("Clear")
        self.managed_by_change_btn.clicked.connect(self.select_managed_by)
        self.managed_by_clear_btn.clicked.connect(self.clear_managed_by)

        name_row.addWidget(self.managed_by_name_edit)
        name_row.addWidget(self.managed_by_change_btn)
        name_row.addWidget(self.managed_by_properties_btn)
        name_row.addWidget(self.managed_by_clear_btn)

        name_container = QWidget()
        name_container.setLayout(name_row)
        form.addRow("Name:", name_container)

        self.managed_by_office_edit = self._readonly_line("")
        self.managed_by_street_edit = QTextEdit()
        self.managed_by_street_edit.setReadOnly(True)
        self.managed_by_street_edit.setPlainText("")
        self.managed_by_state_edit = self._readonly_line("")
        self.managed_by_country_edit = self._readonly_line("")
        self.managed_by_phone_edit = self._readonly_line("")
        self.managed_by_fax_edit = self._readonly_line("")

        form.addRow("Office:", self.managed_by_office_edit)
        form.addRow("Street:", self.managed_by_street_edit)
        form.addRow("State/Province:", self.managed_by_state_edit)
        form.addRow("Country/Region:", self.managed_by_country_edit)
        form.addRow("Telephone Number:", self.managed_by_phone_edit)
        form.addRow("Fax Number:", self.managed_by_fax_edit)

        self._load_managed_by_details(self.original_managed_by)
        self.refresh_managed_by_buttons()
        return tab

    def build_attributes_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.show_empty_attributes_checkbox = QCheckBox("Show attributes with no values")
        self.show_empty_attributes_checkbox.setChecked(self.show_empty_attributes)
        self.show_empty_attributes_checkbox.toggled.connect(self.on_show_empty_attributes_toggled)
        layout.addWidget(self.show_empty_attributes_checkbox)

        editor_layout = QHBoxLayout()
        self.attributes_list = QListWidget()
        self.attributes_list.currentTextChanged.connect(self.on_attribute_selected)
        self.attributes_list.itemDoubleClicked.connect(self.on_attribute_double_clicked)

        right_col = QVBoxLayout()
        self.attribute_name_label = QLabel("Select an attribute")
        self.attribute_value_edit = QTextEdit()
        self.attribute_value_edit.setReadOnly(True)
        right_col.addWidget(self.attribute_name_label)
        right_col.addWidget(self.attribute_value_edit)

        editor_layout.addWidget(self.attributes_list, 1)
        editor_layout.addLayout(right_col, 2)
        layout.addLayout(editor_layout)

        self.refresh_attributes_list()
        return tab

    def _attribute_has_values(self, attr_name: str) -> bool:
        values = self.attribute_values.get(attr_name, [])
        return any(v.strip() for v in values)

    def refresh_attributes_list(self, preferred_attr: Optional[str] = None) -> None:
        current_attr = preferred_attr if preferred_attr is not None else self.attributes_list.currentItem().text() if self.attributes_list.currentItem() else ""
        visible_attrs = [
            attr_name
            for attr_name in sorted(self.attribute_values, key=str.lower)
            if self.show_empty_attributes or self._attribute_has_values(attr_name)
        ]
        self.attributes_list.blockSignals(True)
        self.attributes_list.clear()
        for attr_name in visible_attrs:
            self.attributes_list.addItem(attr_name)
        self.attributes_list.blockSignals(False)

        if not visible_attrs:
            self.selected_attribute = None
            self.on_attribute_selected("")
            return

        target_attr = current_attr if current_attr in visible_attrs else visible_attrs[0]
        for idx in range(self.attributes_list.count()):
            if self.attributes_list.item(idx).text() == target_attr:
                self.attributes_list.setCurrentRow(idx)
                break
        self.on_attribute_selected(target_attr)

    def on_show_empty_attributes_toggled(self, checked: bool) -> None:
        self.show_empty_attributes = checked
        if callable(self.on_toggle_show_empty_attributes):
            self.on_toggle_show_empty_attributes(checked)
        self.refresh_attributes_list()

    def on_attribute_selected(self, attr_name: str) -> None:
        if not self.attribute_name_label or not self.attribute_value_edit:
            return

        if not attr_name:
            self.attribute_name_label.setText("Select an attribute")
            self.attribute_value_edit.clear()
            return

        values = self.attribute_values.get(attr_name, [])
        is_read_only = attr_name in self.NON_EDITABLE_ATTRIBUTES
        if is_read_only:
            status = "(read-only)"
        else:
            status = "(double-click to edit)"
        self.attribute_name_label.setText(f"{attr_name} {status}")
        self.attribute_value_edit.setPlainText("\n".join(values))

    def _is_attribute_integer(self, attr_name: str, values: list[str]) -> bool:
        schema_info = self.ldap.get_attribute_schema_info(attr_name)
        if schema_info.get("is_integer") is True:
            return True
        if schema_info.get("is_integer") is False:
            return False
        if not values:
            return False
        try:
            int(values[0])
            return True
        except ValueError:
            return False

    def _is_attribute_multi_valued(self, attr_name: str, values: list[str]) -> bool:
        schema_info = self.ldap.get_attribute_schema_info(attr_name)
        if schema_info.get("single_valued") is False:
            return True
        if schema_info.get("single_valued") is True:
            return False
        return len(values) > 1 or attr_name.lower() in {"serviceprincipalname"}

    def on_attribute_double_clicked(self, item: QListWidgetItem) -> None:
        attr_name = item.text().strip()
        if not attr_name or attr_name in self.NON_EDITABLE_ATTRIBUTES:
            return

        current_values = list(self.attribute_values.get(attr_name, []))
        if self._is_attribute_multi_valued(attr_name, current_values):
            editor = MultiValuedStringEditorDialog(attr_name, current_values, self)
            if editor.exec() != QDialog.Accepted:
                return
            new_values = editor.edited_values()
        else:
            is_integer = self._is_attribute_integer(attr_name, current_values)
            editor_title = "Integer Attribute Editor" if is_integer else "String Attribute Editor"
            editor = SingleValueAttributeEditorDialog(editor_title, current_values[0] if current_values else "", self)
            if editor.exec() != QDialog.Accepted:
                return
            new_value = editor.edited_value()
            if is_integer and new_value:
                try:
                    int(new_value)
                except ValueError:
                    QMessageBox.warning(self, "Invalid value", "Please enter a valid integer value.")
                    return
            new_values = [new_value] if new_value else []

        self.attribute_values[attr_name] = new_values
        self.refresh_attributes_list(preferred_attr=attr_name)
        self.refresh_apply_button_state()

    def _current_member_of_dns(self, include_primary: bool = False) -> list[str]:
        dns: list[str] = []
        for row in range(self.member_of_table.rowCount()):
            dn_item = self.member_of_table.item(row, 1)
            if not dn_item or not dn_item.text().strip():
                continue
            is_primary = bool(dn_item.data(Qt.UserRole))
            if is_primary and not include_primary:
                continue
            dns.append(dn_item.text().strip())
        return dns

    def refresh_member_of_remove_button_state(self) -> None:
        can_remove = False
        for idx in self.member_of_table.selectionModel().selectedRows():
            dn_item = self.member_of_table.item(idx.row(), 1)
            if dn_item and not bool(dn_item.data(Qt.UserRole)):
                can_remove = True
                break
        self.member_of_remove_btn.setEnabled(can_remove)

    def _current_delegation_mode(self) -> str:
        if self.delegate_any_radio.isChecked():
            return "any"
        if self.delegate_specified_radio.isChecked():
            return "specified"
        return "none"

    def refresh_delegation_controls(self) -> None:
        if not (self.delegate_none_radio.isChecked() or self.delegate_any_radio.isChecked() or self.delegate_specified_radio.isChecked()):
            self.delegate_none_radio.setChecked(True)
        specified_only = self.delegate_specified_radio.isChecked()
        self.delegate_kerberos_only_radio.setEnabled(specified_only)
        self.delegate_any_auth_radio.setEnabled(specified_only)
        self.delegation_add_btn.setEnabled(specified_only)

        has_selection = bool(self.delegation_services_table.selectionModel().selectedRows())
        has_rows = self.delegation_services_table.rowCount() > 0
        self.delegation_remove_btn.setEnabled(specified_only and has_rows and has_selection)
        self.refresh_apply_button_state()

    def add_delegation_service(self) -> None:
        value, ok = QInputDialog.getText(
            self,
            "Add Delegated Service",
            "Service principal name (for example: cifs/server.example.com):",
        )
        value = value.strip()
        if not ok or not value:
            return

        existing = set(self._delegation_services_from_table())
        if value in existing:
            return

        row = self.delegation_services_table.rowCount()
        self.delegation_services_table.insertRow(row)
        service_type, target, port, full_value = self._parse_delegation_service(value)
        self.delegation_services_table.setItem(row, 0, QTableWidgetItem(service_type))
        self.delegation_services_table.setItem(row, 1, QTableWidgetItem(target))
        self.delegation_services_table.setItem(row, 2, QTableWidgetItem(port))
        self.delegation_services_table.setItem(row, 3, QTableWidgetItem(full_value))
        self.refresh_delegation_controls()

    def remove_selected_delegation_services(self) -> None:
        rows = sorted({idx.row() for idx in self.delegation_services_table.selectionModel().selectedRows()}, reverse=True)
        for row in rows:
            self.delegation_services_table.removeRow(row)
        self.refresh_delegation_controls()

    def add_group_memberships(self) -> None:
        group_search_base = self.ldap.get_default_naming_context() or self.search_base
        dlg = SelectDirectoryObjectsDialog(
            self.ldap,
            group_search_base,
            self,
            search_options=[("Groups", SEARCH_FILTER_GROUPS)],
        )
        if dlg.exec() != QDialog.Accepted:
            return

        existing_dns = set(self._current_member_of_dns(include_primary=True))
        for obj in dlg.selected_objects():
            if obj.object_type != "Group" or obj.dn in existing_dns:
                continue
            row = self.member_of_table.rowCount()
            self.member_of_table.insertRow(row)
            name_item = QTableWidgetItem(obj.name)
            name_item.setIcon(icon_for_directory_object(self.style(), obj))
            dn_item = QTableWidgetItem(obj.dn)
            dn_item.setData(Qt.UserRole, False)
            self.member_of_table.setItem(row, 0, name_item)
            self.member_of_table.setItem(row, 1, dn_item)
            existing_dns.add(obj.dn)
        self.refresh_member_of_remove_button_state()
        self.refresh_apply_button_state()

    def remove_selected_group_memberships(self) -> None:
        rows = sorted({idx.row() for idx in self.member_of_table.selectionModel().selectedRows()}, reverse=True)
        for row in rows:
            dn_item = self.member_of_table.item(row, 1)
            if dn_item and bool(dn_item.data(Qt.UserRole)):
                continue
            self.member_of_table.removeRow(row)
        self.refresh_member_of_remove_button_state()
        self.refresh_apply_button_state()

    def _on_managed_by_changed(self) -> None:
        if not self.managed_by_name_edit.text().strip():
            self._set_managed_by_details({})
        self.refresh_managed_by_buttons()
        self.refresh_apply_button_state()

    def _set_managed_by_details(self, managed_by_attrs: dict[str, list[str]]) -> None:
        self.managed_by_office_edit.setText(self._single_attr(managed_by_attrs, "physicalDeliveryOfficeName"))
        self.managed_by_street_edit.setPlainText(self._single_attr(managed_by_attrs, "streetAddress"))
        self.managed_by_state_edit.setText(self._single_attr(managed_by_attrs, "st"))
        self.managed_by_country_edit.setText(self._single_attr(managed_by_attrs, "co"))
        self.managed_by_phone_edit.setText(self._single_attr(managed_by_attrs, "telephoneNumber"))
        self.managed_by_fax_edit.setText(self._single_attr(managed_by_attrs, "facsimileTelephoneNumber"))

    def _load_managed_by_details(self, managed_by_dn: str) -> None:
        managed_by_dn = managed_by_dn.strip()
        if not managed_by_dn:
            self._set_managed_by_details({})
            return

        try:
            managed_by_attrs = self.ldap.get_object_attributes(managed_by_dn)
        except Exception:
            managed_by_attrs = {}

        self._set_managed_by_details(managed_by_attrs)

    def refresh_managed_by_buttons(self) -> None:
        has_value = bool(self.managed_by_name_edit.text().strip())
        self.managed_by_properties_btn.setEnabled(has_value)
        self.managed_by_clear_btn.setEnabled(has_value)

    def select_managed_by(self) -> None:
        managed_by_search_base = self.ldap.get_default_naming_context() or self.search_base
        dlg = SelectDirectoryObjectsDialog(
            self.ldap,
            managed_by_search_base,
            self,
            search_options=[
                ("Users, Contacts, and Groups", SEARCH_FILTER_USERS_CONTACTS_GROUPS),
                ("Groups", SEARCH_FILTER_GROUPS),
            ],
        )
        if dlg.exec() != QDialog.Accepted:
            return
        selected = dlg.selected_objects()
        if not selected:
            return
        self.managed_by_name_edit.setText(selected[0].dn)
        self._load_managed_by_details(selected[0].dn)

    def clear_managed_by(self) -> None:
        self.managed_by_name_edit.clear()
        self._set_managed_by_details({})

    def has_pending_changes(self) -> bool:
        if self.description_edit.text().strip() != self.original_description:
            return True
        if self.location_edit.text().strip() != self.original_location:
            return True
        if self.managed_by_name_edit.text().strip() != self.original_managed_by:
            return True

        current_groups = sorted(self._current_member_of_dns(), key=str.lower)
        if current_groups != sorted(self.original_group_dns, key=str.lower):
            return True

        current_delegation_mode = self._current_delegation_mode()
        if current_delegation_mode != self.original_delegation_mode:
            return True
        if current_delegation_mode == "specified":
            if self.delegate_any_auth_radio.isChecked() != self.original_protocol_any_auth:
                return True
            if self._delegation_services_from_table() != self.original_delegation_services:
                return True

        for attr_name in self.attribute_values:
            if attr_name in self.NON_EDITABLE_ATTRIBUTES:
                continue
            if attr_name in {"description", "location", "managedBy", "msDS-AllowedToDelegateTo", "memberOf", "member"}:
                continue
            current_values = self.attribute_values.get(attr_name, [])
            original_values = self.original_attribute_values.get(attr_name, [])
            if current_values != original_values:
                return True

        if self.security_editor.has_pending_changes():
            return True

        return False

    def refresh_apply_button_state(self) -> None:
        if self.apply_button:
            self.apply_button.setEnabled(self.has_pending_changes())

    def apply_member_of_changes(self) -> None:
        desired = set(self._current_member_of_dns())
        original = set(self.original_group_dns)

        add_dns = sorted(desired - original)
        remove_dns = sorted(original - desired)

        for group_dn in add_dns:
            self.ldap.add_group_member(group_dn, self.computer_obj.dn)
        for group_dn in remove_dns:
            self.ldap.remove_group_member(group_dn, self.computer_obj.dn)

        self.original_group_dns = sorted(desired, key=str.lower)

    def apply_attribute_changes(self) -> None:
        description_value = self.description_edit.text().strip()
        if description_value != self.original_description:
            self.ldap.replace_object_attribute_values(self.computer_obj.dn, "description", [description_value] if description_value else [])
            self.original_description = description_value
            self.attribute_values["description"] = [description_value] if description_value else []
            self.original_attribute_values["description"] = list(self.attribute_values["description"])

        location_value = self.location_edit.text().strip()
        if location_value != self.original_location:
            self.ldap.replace_object_attribute_values(self.computer_obj.dn, "location", [location_value] if location_value else [])
            self.original_location = location_value
            self.attribute_values["location"] = [location_value] if location_value else []
            self.original_attribute_values["location"] = list(self.attribute_values["location"])

        managed_by_value = self.managed_by_name_edit.text().strip()
        if managed_by_value != self.original_managed_by:
            self.ldap.replace_object_attribute_values(self.computer_obj.dn, "managedBy", [managed_by_value] if managed_by_value else [])
            self.original_managed_by = managed_by_value
            self.attribute_values["managedBy"] = [managed_by_value] if managed_by_value else []
            self.original_attribute_values["managedBy"] = list(self.attribute_values["managedBy"])

        for attr_name in sorted(self.attribute_values):
            if attr_name in self.NON_EDITABLE_ATTRIBUTES:
                continue
            if attr_name in {"description", "location", "managedBy", "msDS-AllowedToDelegateTo", "memberOf", "member"}:
                continue
            current_values = self.attribute_values.get(attr_name, [])
            original_values = self.original_attribute_values.get(attr_name, [])
            if current_values == original_values:
                continue
            self.ldap.replace_object_attribute_values(self.computer_obj.dn, attr_name, current_values)
            self.original_attribute_values[attr_name] = list(current_values)

    def apply_delegation_changes(self) -> None:
        mode = self._current_delegation_mode()
        services = self._delegation_services_from_table() if mode == "specified" else []

        new_uac = self.current_uac_value & ~(0x80000 | 0x1000000)
        if mode == "any":
            new_uac |= 0x80000
        elif mode == "specified" and self.delegate_any_auth_radio.isChecked():
            new_uac |= 0x1000000

        if new_uac != self.current_uac_value:
            self.ldap.set_user_account_control(self.computer_obj.dn, new_uac)
            self.current_uac_value = new_uac

        if services != self.original_delegation_services:
            self.ldap.replace_object_attribute_values(self.computer_obj.dn, "msDS-AllowedToDelegateTo", services)
            self.original_delegation_services = list(services)
            self.attribute_values["msDS-AllowedToDelegateTo"] = list(services)
            self.original_attribute_values["msDS-AllowedToDelegateTo"] = list(services)

        self.original_delegation_mode = mode
        self.original_protocol_any_auth = self.delegate_any_auth_radio.isChecked()

    def apply_changes(self) -> bool:
        try:
            with busy_cursor():
                self.apply_member_of_changes()
                self.apply_attribute_changes()
                self.apply_delegation_changes()
                if not self.security_editor.apply_security_changes(reload_after_save=False):
                    return False
        except Exception as e:
            QMessageBox.critical(self, "Apply failed", str(e))
            return False

        current_item = self.security_editor.principal_list.currentItem()
        selected_sid = str(current_item.data(Qt.UserRole)) if current_item else ""
        self.security_editor.reload_from_directory(select_sid=selected_sid)
        self.refresh_apply_button_state()
        return True

    def on_ok(self) -> None:
        if self.apply_changes():
            self.accept()


class UserPropertiesDialog(QDialog):
    NON_EDITABLE_ATTRIBUTES = {
        "distinguishedName",
        "objectClass",
        "objectGUID",
        "objectSid",
        "whenCreated",
        "whenChanged",
        "uSNCreated",
        "uSNChanged",
        "memberOf",
        "member",
    }

    UAC_FLAGS: list[tuple[str, int]] = [
        ("Account is disabled", 0x0002),
        ("Account is locked out", 0x0010),
        ("Password not required", 0x0020),
        ("Password cannot change", 0x0040),
        ("Password never expires", 0x10000),
        ("Smart card required", 0x40000),
        ("Trusted for delegation", 0x80000),
    ]

    def __init__(
        self,
        ldap: LdapManager,
        obj: LdapObject,
        attrs: dict[str, list[str]],
        search_base: str,
        show_empty_attributes: bool = False,
        on_toggle_show_empty_attributes=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(obj.name)
        self.resize(920, 650)
        self.ldap = ldap
        self.user_obj = obj
        self.search_base = search_base
        self.original_group_dns: list[str] = []
        self.primary_group_dn: Optional[str] = None
        self.current_uac_value = 0
        self.initially_locked = False
        self.uac_checkboxes: list[tuple[QCheckBox, int]] = []
        self.original_attribute_values: dict[str, list[str]] = {k: [str(v) for v in vals] for k, vals in attrs.items()}
        self.attribute_values: dict[str, list[str]] = {k: [str(v) for v in vals] for k, vals in attrs.items()}
        self.selected_attribute: Optional[str] = None
        self.loading_attribute_text = False
        self.attribute_name_label: Optional[QLabel] = None
        self.attribute_value_edit: Optional[QTextEdit] = None
        self.show_empty_attributes = bool(show_empty_attributes)
        self.on_toggle_show_empty_attributes = on_toggle_show_empty_attributes
        self.apply_button: Optional[QPushButton] = None

        tabs = QTabWidget()
        tabs.addTab(self.build_general_tab(obj, attrs), "General")
        tabs.addTab(self.build_address_tab(attrs), "Address")
        tabs.addTab(self.build_account_tab(attrs), "Account")
        tabs.addTab(self.build_profile_tab(attrs), "Profile")
        tabs.addTab(self.build_member_of_tab(attrs), "Member Of")
        tabs.addTab(self.build_object_tab(obj, attrs), "Object")
        tabs.addTab(self.build_attributes_tab(attrs), "Attribute Editor")
        self.security_editor = build_acl_viewer_tab(self.ldap, obj.dn, self.search_base, show_apply_button=False)
        self.security_editor.changed.connect(self.refresh_apply_button_state)
        tabs.addTab(self.security_editor, "Security")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.Apply)
        buttons.accepted.connect(self.on_ok)
        buttons.rejected.connect(self.reject)
        apply_button = buttons.button(QDialogButtonBox.Apply)
        if apply_button:
            self.apply_button = apply_button
            apply_button.clicked.connect(self.apply_changes)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)
        self.refresh_apply_button_state()

    def _single_attr(self, attrs: dict[str, list[str]], attr: str) -> str:
        values = attrs.get(attr, [])
        return values[0] if values else ""

    def _readonly_line(self, value: str) -> QLineEdit:
        edit = QLineEdit(value)
        edit.setReadOnly(True)
        return edit

    def build_general_tab(self, obj: LdapObject, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.addRow("First name:", self._readonly_line(self._single_attr(attrs, "givenName")))
        form.addRow("Initials:", self._readonly_line(self._single_attr(attrs, "initials")))
        form.addRow("Last name:", self._readonly_line(self._single_attr(attrs, "sn")))
        form.addRow("Display name:", self._readonly_line(self._single_attr(attrs, "displayName") or obj.name))
        form.addRow("Description:", self._readonly_line(self._single_attr(attrs, "description")))
        form.addRow("Office:", self._readonly_line(self._single_attr(attrs, "physicalDeliveryOfficeName")))
        form.addRow("Telephone number:", self._readonly_line(self._single_attr(attrs, "telephoneNumber")))
        form.addRow("E-mail:", self._readonly_line(self._single_attr(attrs, "mail")))
        form.addRow("Web page:", self._readonly_line(self._single_attr(attrs, "wWWHomePage")))
        return tab

    def build_address_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.addRow("Street:", self._readonly_line(self._single_attr(attrs, "streetAddress")))
        form.addRow("P.O. box:", self._readonly_line(self._single_attr(attrs, "postOfficeBox")))
        form.addRow("City:", self._readonly_line(self._single_attr(attrs, "l")))
        form.addRow("State/province:", self._readonly_line(self._single_attr(attrs, "st")))
        form.addRow("ZIP/Postal code:", self._readonly_line(self._single_attr(attrs, "postalCode")))
        form.addRow("Country/region:", self._readonly_line(self._single_attr(attrs, "co")))
        return tab

    def build_account_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        form = QFormLayout()

        form.addRow("User logon name:", self._readonly_line(self._single_attr(attrs, "userPrincipalName")))
        form.addRow("User logon name (pre-Windows 2000):", self._readonly_line(self._single_attr(attrs, "sAMAccountName")))
        form.addRow("Logon script:", self._readonly_line(self._single_attr(attrs, "scriptPath")))
        form.addRow("Home folder:", self._readonly_line(self._single_attr(attrs, "homeDirectory")))

        uac_raw = self._single_attr(attrs, "userAccountControl")
        self.uac_value_line = self._readonly_line(uac_raw)
        form.addRow("userAccountControl:", self.uac_value_line)
        layout.addLayout(form)

        flags_label = QLabel("Account options")
        layout.addWidget(flags_label)

        flag_values = 0
        try:
            flag_values = int(uac_raw) if uac_raw else 0
        except ValueError:
            flag_values = 0
        self.current_uac_value = flag_values

        lockout_raw = self._single_attr(attrs, "lockoutTime")
        try:
            self.initially_locked = int(lockout_raw) > 0 if lockout_raw else False
        except ValueError:
            self.initially_locked = False

        for label, bitmask in self.UAC_FLAGS:
            box = QCheckBox(label)
            if bitmask == 0x0010:
                box.setChecked(self.initially_locked)
                box.setToolTip("Active Directory controls lockout state via lockoutTime.")
            else:
                box.setChecked(bool(flag_values & bitmask))
            box.stateChanged.connect(self.refresh_apply_button_state)
            self.uac_checkboxes.append((box, bitmask))
            layout.addWidget(box)

        layout.addStretch()
        return tab

    def build_profile_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.addRow("Profile path:", self._readonly_line(self._single_attr(attrs, "profilePath")))
        form.addRow("Logon script:", self._readonly_line(self._single_attr(attrs, "scriptPath")))
        form.addRow("Home drive:", self._readonly_line(self._single_attr(attrs, "homeDrive")))
        form.addRow("Home folder:", self._readonly_line(self._single_attr(attrs, "homeDirectory")))
        return tab

    def build_member_of_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.member_of_table = QTableWidget()
        self.member_of_table.setColumnCount(2)
        self.member_of_table.setHorizontalHeaderLabels(["Name", "Distinguished Name"])
        self.member_of_table.verticalHeader().setVisible(False)
        self.member_of_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.member_of_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.member_of_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.member_of_table.itemSelectionChanged.connect(self.refresh_member_of_remove_button_state)

        groups = list(attrs.get("memberOf", []))
        self.original_group_dns = sorted(groups, key=str.lower)

        self.primary_group_dn = None
        primary_group = self.ldap.get_object_primary_group(self.user_obj.dn)
        if primary_group is not None:
            self.primary_group_dn = primary_group.dn
            if primary_group.dn not in groups:
                groups.append(primary_group.dn)

        self.member_of_table.setRowCount(len(groups))
        for row, dn in enumerate(sorted(groups, key=str.lower)):
            short_name = dn.split(",", 1)[0].split("=", 1)[-1] if "=" in dn else dn
            name_item = QTableWidgetItem(short_name)
            dn_item = QTableWidgetItem(dn)
            is_primary = bool(self.primary_group_dn and dn.lower() == self.primary_group_dn.lower())
            dn_item.setData(Qt.UserRole, is_primary)
            if is_primary:
                name_item.setToolTip("Primary group")
                dn_item.setToolTip("Primary group")
            self.member_of_table.setItem(row, 0, name_item)
            self.member_of_table.setItem(row, 1, dn_item)

        button_row = QHBoxLayout()
        self.member_of_add_btn = QPushButton("Add...")
        self.member_of_remove_btn = QPushButton("Remove")
        button_row.addWidget(self.member_of_add_btn)
        button_row.addWidget(self.member_of_remove_btn)
        button_row.addStretch()
        self.member_of_add_btn.clicked.connect(self.add_group_memberships)
        self.member_of_remove_btn.clicked.connect(self.remove_selected_group_memberships)

        self.member_of_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.member_of_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.member_of_table)
        layout.addLayout(button_row)
        self.refresh_member_of_remove_button_state()
        return tab

    def _current_member_of_dns(self, include_primary: bool = False) -> list[str]:
        dns: list[str] = []
        for row in range(self.member_of_table.rowCount()):
            dn_item = self.member_of_table.item(row, 1)
            if not dn_item or not dn_item.text().strip():
                continue
            is_primary = bool(dn_item.data(Qt.UserRole))
            if is_primary and not include_primary:
                continue
            dns.append(dn_item.text().strip())
        return dns

    def refresh_member_of_remove_button_state(self) -> None:
        can_remove = False
        for idx in self.member_of_table.selectionModel().selectedRows():
            dn_item = self.member_of_table.item(idx.row(), 1)
            if dn_item and not bool(dn_item.data(Qt.UserRole)):
                can_remove = True
                break
        self.member_of_remove_btn.setEnabled(can_remove)

    def add_group_memberships(self) -> None:
        group_search_base = self.ldap.get_default_naming_context() or self.search_base
        dlg = SelectDirectoryObjectsDialog(
            self.ldap,
            group_search_base,
            self,
            search_options=[("Groups", SEARCH_FILTER_GROUPS)],
        )
        if dlg.exec() != QDialog.Accepted:
            return

        existing_dns = set(self._current_member_of_dns(include_primary=True))
        for obj in dlg.selected_objects():
            if obj.object_type != "Group" or obj.dn in existing_dns:
                continue
            row = self.member_of_table.rowCount()
            self.member_of_table.insertRow(row)
            name_item = QTableWidgetItem(obj.name)
            name_item.setIcon(icon_for_directory_object(self.style(), obj))
            dn_item = QTableWidgetItem(obj.dn)
            dn_item.setData(Qt.UserRole, False)
            self.member_of_table.setItem(row, 0, name_item)
            self.member_of_table.setItem(row, 1, dn_item)
            existing_dns.add(obj.dn)
        self.refresh_member_of_remove_button_state()
        self.refresh_apply_button_state()

    def remove_selected_group_memberships(self) -> None:
        rows = sorted({idx.row() for idx in self.member_of_table.selectionModel().selectedRows()}, reverse=True)
        for row in rows:
            dn_item = self.member_of_table.item(row, 1)
            if dn_item and bool(dn_item.data(Qt.UserRole)):
                continue
            self.member_of_table.removeRow(row)
        self.refresh_member_of_remove_button_state()
        self.refresh_apply_button_state()

    def _edited_uac_and_unlock(self) -> tuple[int, bool]:
        new_uac = self.current_uac_value
        should_unlock = False

        for box, bitmask in self.uac_checkboxes:
            checked = box.isChecked()
            if bitmask == 0x0010:
                if (not checked) and self.initially_locked:
                    should_unlock = True
                continue
            if checked:
                new_uac |= bitmask
            else:
                new_uac &= ~bitmask

        return new_uac, should_unlock

    def has_pending_changes(self) -> bool:
        edited_uac, should_unlock = self._edited_uac_and_unlock()
        if edited_uac != self.current_uac_value or should_unlock:
            return True

        current_groups = sorted(self._current_member_of_dns(), key=str.lower)
        if current_groups != sorted(self.original_group_dns, key=str.lower):
            return True

        for attr_name in self.attribute_values:
            current_values = self.attribute_values.get(attr_name, [])
            original_values = self.original_attribute_values.get(attr_name, [])
            if current_values != original_values:
                return True

        if self.security_editor.has_pending_changes():
            return True

        return False

    def refresh_apply_button_state(self) -> None:
        if self.apply_button:
            self.apply_button.setEnabled(self.has_pending_changes())

    def apply_account_changes(self) -> None:
        for box, bitmask in self.uac_checkboxes:
            if bitmask == 0x0010 and box.isChecked() and not self.initially_locked:
                box.setChecked(False)

        new_uac, should_unlock = self._edited_uac_and_unlock()

        if new_uac != self.current_uac_value:
            self.ldap.set_user_account_control(self.user_obj.dn, new_uac)
            self.current_uac_value = new_uac
            self.uac_value_line.setText(str(new_uac))

        if should_unlock:
            self.ldap.unlock_account(self.user_obj.dn)
            self.initially_locked = False

    def apply_attribute_changes(self) -> None:
        for attr_name in sorted(self.attribute_values):
            if attr_name in self.NON_EDITABLE_ATTRIBUTES:
                continue
            current_values = self.attribute_values.get(attr_name, [])
            original_values = self.original_attribute_values.get(attr_name, [])
            if current_values == original_values:
                continue
            self.ldap.replace_object_attribute_values(self.user_obj.dn, attr_name, current_values)
            self.original_attribute_values[attr_name] = list(current_values)

    def apply_member_of_changes(self) -> None:
        desired = set(self._current_member_of_dns())
        original = set(self.original_group_dns)

        add_dns = sorted(desired - original)
        remove_dns = sorted(original - desired)

        for group_dn in add_dns:
            self.ldap.add_group_member(group_dn, self.user_obj.dn)

        for group_dn in remove_dns:
            self.ldap.remove_group_member(group_dn, self.user_obj.dn)

        self.original_group_dns = sorted(desired, key=str.lower)

    def apply_changes(self) -> None:
        try:
            with busy_cursor():
                self.apply_account_changes()
                self.apply_member_of_changes()
                self.apply_attribute_changes()
                current_item = self.security_editor.principal_list.currentItem()
                selected_sid = str(current_item.data(Qt.UserRole)) if current_item else ""
                if not self.security_editor.apply_security_changes(reload_after_save=False):
                    return
                self.security_editor.reload_from_directory(select_sid=selected_sid)
            self.refresh_apply_button_state()
        except Exception as e:
            QMessageBox.critical(self, "Apply failed", str(e))

    def on_ok(self) -> None:
        try:
            with busy_cursor():
                self.apply_account_changes()
                self.apply_member_of_changes()
                self.apply_attribute_changes()
                current_item = self.security_editor.principal_list.currentItem()
                selected_sid = str(current_item.data(Qt.UserRole)) if current_item else ""
                if not self.security_editor.apply_security_changes(reload_after_save=False):
                    return
                self.security_editor.reload_from_directory(select_sid=selected_sid)
        except Exception as e:
            QMessageBox.critical(self, "Apply failed", str(e))
            return
        self.accept()


    @staticmethod
    def dn_to_canonical_name(dn: str) -> str:
        parts = [part.strip() for part in dn.split(",") if part.strip()]
        dc_parts: list[str] = []
        path_parts: list[str] = []

        for part in reversed(parts):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key_upper = key.upper()
            if key_upper == "DC":
                dc_parts.append(value)
            elif key_upper in {"OU", "CN"}:
                path_parts.append(value)

        domain = ".".join(dc_parts)
        path = "/".join(path_parts)
        if domain and path:
            return f"{domain}/{path}"
        return domain or path or dn

    def build_object_tab(self, obj: LdapObject, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.addRow("Canonical name:", self._readonly_line(self.dn_to_canonical_name(obj.dn)))
        form.addRow("Distinguished name:", self._readonly_line(obj.dn))
        form.addRow("Object class:", self._readonly_line(obj.object_type))
        form.addRow("Created:", self._readonly_line(self._single_attr(attrs, "whenCreated")))
        form.addRow("Modified:", self._readonly_line(self._single_attr(attrs, "whenChanged")))
        return tab

    def build_attributes_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.show_empty_attributes_checkbox = QCheckBox("Show attributes with no values")
        self.show_empty_attributes_checkbox.setChecked(self.show_empty_attributes)
        self.show_empty_attributes_checkbox.toggled.connect(self.on_show_empty_attributes_toggled)
        layout.addWidget(self.show_empty_attributes_checkbox)

        editor_layout = QHBoxLayout()
        self.attributes_list = QListWidget()
        self.attributes_list.currentTextChanged.connect(self.on_attribute_selected)
        self.attributes_list.itemDoubleClicked.connect(self.on_attribute_double_clicked)

        right_col = QVBoxLayout()
        self.attribute_name_label = QLabel("Select an attribute")
        self.attribute_value_edit = QTextEdit()
        self.attribute_value_edit.setReadOnly(True)
        right_col.addWidget(self.attribute_name_label)
        right_col.addWidget(self.attribute_value_edit)

        editor_layout.addWidget(self.attributes_list, 1)
        editor_layout.addLayout(right_col, 2)
        layout.addLayout(editor_layout)

        self.refresh_attributes_list()
        return tab

    def _attribute_has_values(self, attr_name: str) -> bool:
        values = self.attribute_values.get(attr_name, [])
        return any(v.strip() for v in values)

    def refresh_attributes_list(self, preferred_attr: Optional[str] = None) -> None:
        current_attr = preferred_attr if preferred_attr is not None else self.attributes_list.currentItem().text() if self.attributes_list.currentItem() else ""
        visible_attrs = [
            attr_name
            for attr_name in sorted(self.attribute_values, key=str.lower)
            if self.show_empty_attributes or self._attribute_has_values(attr_name)
        ]
        self.attributes_list.blockSignals(True)
        self.attributes_list.clear()
        for attr_name in visible_attrs:
            self.attributes_list.addItem(attr_name)
        self.attributes_list.blockSignals(False)

        if not visible_attrs:
            self.selected_attribute = None
            self.on_attribute_selected("")
            return

        target_attr = current_attr if current_attr in visible_attrs else visible_attrs[0]
        for idx in range(self.attributes_list.count()):
            if self.attributes_list.item(idx).text() == target_attr:
                self.attributes_list.setCurrentRow(idx)
                break
        self.on_attribute_selected(target_attr)

    def on_show_empty_attributes_toggled(self, checked: bool) -> None:
        self.show_empty_attributes = checked
        if callable(self.on_toggle_show_empty_attributes):
            self.on_toggle_show_empty_attributes(checked)
        self.refresh_attributes_list()

    def on_attribute_selected(self, attr_name: str) -> None:
        self.selected_attribute = attr_name if attr_name else None
        if not self.attribute_name_label or not self.attribute_value_edit:
            return

        if not attr_name:
            self.attribute_name_label.setText("Select an attribute")
            self.attribute_value_edit.clear()
            self.attribute_value_edit.setReadOnly(True)
            return

        values = self.attribute_values.get(attr_name, [])
        is_read_only = attr_name in self.NON_EDITABLE_ATTRIBUTES
        self.attribute_name_label.setText(
            f"{attr_name} {'(read-only)' if is_read_only else '(double-click to edit)'}"
        )
        self.loading_attribute_text = True
        self.attribute_value_edit.setPlainText("\n".join(values))
        self.loading_attribute_text = False
        self.attribute_value_edit.setReadOnly(True)

    def _is_attribute_integer(self, attr_name: str, values: list[str]) -> bool:
        schema_info = self.ldap.get_attribute_schema_info(attr_name)
        if schema_info.get("is_integer") is True:
            return True
        if schema_info.get("is_integer") is False:
            return False
        if not values:
            return False
        try:
            int(values[0])
            return True
        except ValueError:
            return False

    def _is_attribute_multi_valued(self, attr_name: str, values: list[str]) -> bool:
        schema_info = self.ldap.get_attribute_schema_info(attr_name)
        if schema_info.get("single_valued") is False:
            return True
        if schema_info.get("single_valued") is True:
            return False
        return len(values) > 1 or attr_name.lower() in {"serviceprincipalname"}

    def on_attribute_double_clicked(self, item: QListWidgetItem) -> None:
        attr_name = item.text().strip()
        if not attr_name or attr_name in self.NON_EDITABLE_ATTRIBUTES:
            return

        current_values = list(self.attribute_values.get(attr_name, []))
        if self._is_attribute_multi_valued(attr_name, current_values):
            editor = MultiValuedStringEditorDialog(attr_name, current_values, self)
            if editor.exec() != QDialog.Accepted:
                return
            new_values = editor.edited_values()
        else:
            is_integer = self._is_attribute_integer(attr_name, current_values)
            editor_title = "Integer Attribute Editor" if is_integer else "String Attribute Editor"
            editor = SingleValueAttributeEditorDialog(editor_title, current_values[0] if current_values else "", self)
            if editor.exec() != QDialog.Accepted:
                return
            new_value = editor.edited_value()
            if is_integer and new_value:
                try:
                    int(new_value)
                except ValueError:
                    QMessageBox.warning(self, "Invalid value", "Please enter a valid integer value.")
                    return
            new_values = [new_value] if new_value else []

        self.attribute_values[attr_name] = new_values
        self.refresh_attributes_list(preferred_attr=attr_name)
        self.refresh_apply_button_state()

    def on_attribute_text_changed(self) -> None:
        if self.loading_attribute_text or not self.selected_attribute or not self.attribute_value_edit:
            return
        raw_text = self.attribute_value_edit.toPlainText()
        values = [line.strip() for line in raw_text.splitlines() if line.strip()]
        self.attribute_values[self.selected_attribute] = values
        self.refresh_apply_button_state()


class ResetPasswordDialog(QDialog):
    def __init__(self, obj_name: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Reset Password - {obj_name}")

        self.password1_edit = QLineEdit()
        self.password1_edit.setEchoMode(QLineEdit.Password)

        self.password2_edit = QLineEdit()
        self.password2_edit.setEchoMode(QLineEdit.Password)

        form = QFormLayout()
        form.addRow("New password:", self.password1_edit)
        form.addRow("Confirm password:", self.password2_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def passwords(self) -> tuple[str, str]:
        return self.password1_edit.text(), self.password2_edit.text()


class NewUserDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New User")

        self.name_edit = QLineEdit()
        self.sam_edit = QLineEdit()
        self.upn_edit = QLineEdit()
        self.description_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.enable_checkbox = QCheckBox("Enable account after creation")

        form = QFormLayout()
        form.addRow("Name:", self.name_edit)
        form.addRow("Logon name (sAMAccountName):", self.sam_edit)
        form.addRow("User principal name (optional):", self.upn_edit)
        form.addRow("Description (optional):", self.description_edit)
        form.addRow("Initial password (optional):", self.password_edit)
        form.addRow("", self.enable_checkbox)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str, str, str, str, bool]:
        return (
            self.name_edit.text().strip(),
            self.sam_edit.text().strip(),
            self.upn_edit.text().strip(),
            self.description_edit.text().strip(),
            self.password_edit.text(),
            self.enable_checkbox.isChecked(),
        )


class NewGroupDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Group")

        self.name_edit = QLineEdit()
        self.sam_edit = QLineEdit()
        self.description_edit = QLineEdit()
        self.scope_combo = QComboBox()
        self.scope_combo.addItems(["Global", "Domain Local", "Universal"])
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Security", "Distribution"])

        form = QFormLayout()
        form.addRow("Name:", self.name_edit)
        form.addRow("Pre-Windows 2000 name (sAMAccountName):", self.sam_edit)
        form.addRow("Description (optional):", self.description_edit)
        form.addRow("Group scope:", self.scope_combo)
        form.addRow("Group type:", self.type_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str, str, str, bool]:
        return (
            self.name_edit.text().strip(),
            self.sam_edit.text().strip(),
            self.description_edit.text().strip(),
            self.scope_combo.currentText(),
            self.type_combo.currentText() == "Security",
        )


class NewComputerDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Computer")

        self.name_edit = QLineEdit()
        self.sam_edit = QLineEdit()
        self.description_edit = QLineEdit()
        self.enable_checkbox = QCheckBox("Enable computer account")
        self.enable_checkbox.setChecked(True)

        form = QFormLayout()
        form.addRow("Computer name:", self.name_edit)
        form.addRow("Pre-Windows 2000 name (sAMAccountName):", self.sam_edit)
        form.addRow("Description (optional):", self.description_edit)
        form.addRow("", self.enable_checkbox)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str, str, bool]:
        return (
            self.name_edit.text().strip(),
            self.sam_edit.text().strip(),
            self.description_edit.text().strip(),
            self.enable_checkbox.isChecked(),
        )


class SearchDialog(QDialog):
    def __init__(self, base_dn: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Find")

        self.term_edit = QLineEdit()
        self.term_edit.setPlaceholderText("Name, sAMAccountName, displayName...")

        self.scope_combo = QComboBox()
        for label, value in SEARCH_FILTER_OPTIONS:
            self.scope_combo.addItem(label, value)

        form = QFormLayout()
        form.addRow("Find what:", self.term_edit)
        form.addRow("Find objects of type:", self.scope_combo)

        base_label = QLabel(base_dn)
        base_label.setWordWrap(True)
        form.addRow("Search under:", base_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def term(self) -> str:
        return self.term_edit.text().strip()

    def search_mode(self) -> str:
        return str(self.scope_combo.currentData())


class SelectDirectoryObjectsDialog(QDialog):
    def __init__(
        self,
        ldap: LdapManager,
        search_base: str,
        parent=None,
        search_options: list[tuple[str, str]] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Select Users, Contacts, Computers, or Groups")
        self.resize(800, 500)
        self.ldap = ldap
        self.search_base = search_base

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Name, sAMAccountName, displayName...")
        self.search_edit.returnPressed.connect(self.run_search)

        self.search_type_combo = QComboBox()
        options = search_options or SEARCH_FILTER_OPTIONS
        for label, value in options:
            self.search_type_combo.addItem(label, value)
        self.search_type_combo.setEnabled(len(options) > 1)

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.run_search)

        search_row = QHBoxLayout()
        search_row.addWidget(self.search_edit)
        search_row.addWidget(self.search_type_combo)
        search_row.addWidget(self.search_btn)

        self.results = QTableWidget()
        self.results.setColumnCount(3)
        self.results.setHorizontalHeaderLabels(["Name", "Type", "Distinguished Name"])
        self.results.setSelectionBehavior(QTableWidget.SelectRows)
        self.results.setSelectionMode(QTableWidget.ExtendedSelection)
        self.results.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results.verticalHeader().setVisible(False)
        self.results.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.results.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.results.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.results.cellDoubleClicked.connect(lambda *_: self.accept())

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(search_row)
        layout.addWidget(self.results)
        layout.addWidget(buttons)

    def run_search(self, *_args) -> None:
        term = self.search_edit.text().strip() or "*"

        try:
            results = self.ldap.search_directory_objects(
                self.search_base,
                term,
                search_mode=str(self.search_type_combo.currentData()),
            )
        except Exception as e:
            QMessageBox.critical(self, "Search failed", str(e))
            return

        self.results.setRowCount(len(results))
        for row, obj in enumerate(results):
            name_item = QTableWidgetItem(obj.name)
            name_item.setIcon(icon_for_directory_object(self.style(), obj))
            name_item.setData(Qt.UserRole, obj)
            type_item = QTableWidgetItem(obj.object_type)
            dn_item = QTableWidgetItem(obj.dn)
            self.results.setItem(row, 0, name_item)
            self.results.setItem(row, 1, type_item)
            self.results.setItem(row, 2, dn_item)

        if not results:
            QMessageBox.information(self, "Search", "No objects found.")

    def selected_objects(self) -> list[LdapObject]:
        seen_rows = sorted({idx.row() for idx in self.results.selectionModel().selectedRows()})
        out: list[LdapObject] = []
        for row in seen_rows:
            item = self.results.item(row, 0)
            if not item:
                continue
            obj = item.data(Qt.UserRole)
            if isinstance(obj, LdapObject):
                out.append(obj)
        return out


class GroupPropertiesDialog(QDialog):
    NON_EDITABLE_ATTRIBUTES = {
        "distinguishedName",
        "objectClass",
        "objectGUID",
        "objectSid",
        "whenCreated",
        "whenChanged",
        "uSNCreated",
        "uSNChanged",
        "memberOf",
        "member",
    }

    def __init__(
        self,
        ldap: LdapManager,
        group_obj: LdapObject,
        attrs: dict[str, list[str]],
        search_base: str,
        show_empty_attributes: bool = False,
        on_toggle_show_empty_attributes=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(group_obj.name)
        self.resize(900, 600)
        self.ldap = ldap
        self.group_obj = group_obj
        self.attrs = attrs
        self.search_base = search_base
        self.original_member_dns: list[str] = []
        self.original_sam_name = attrs.get("sAMAccountName", [""])[0]
        self.original_description = attrs.get("description", [""])[0]
        self.original_email = attrs.get("mail", [""])[0]
        self.original_managed_by = attrs.get("managedBy", [""])[0]
        self.original_attribute_values: dict[str, list[str]] = {k: [str(v) for v in vals] for k, vals in attrs.items()}
        self.attribute_values: dict[str, list[str]] = {k: [str(v) for v in vals] for k, vals in attrs.items()}
        self.selected_attribute: Optional[str] = None
        self.attribute_name_label: Optional[QLabel] = None
        self.attribute_value_edit: Optional[QTextEdit] = None
        self.show_empty_attributes = bool(show_empty_attributes)
        self.on_toggle_show_empty_attributes = on_toggle_show_empty_attributes
        self.apply_button: Optional[QPushButton] = None

        tabs = QTabWidget()

        general = QWidget()
        general_layout = QFormLayout(general)
        self.sam_name_edit = QLineEdit(attrs.get("sAMAccountName", [""])[0])
        self.description_edit = QLineEdit(attrs.get("description", [""])[0])
        self.email_edit = QLineEdit(attrs.get("mail", [""])[0])
        general_layout.addRow("Group name (pre-Windows 2000):", self.sam_name_edit)
        general_layout.addRow("Description:", self.description_edit)
        general_layout.addRow("E-mail:", self.email_edit)
        tabs.addTab(general, "General")

        members_tab = QWidget()
        members_layout = QVBoxLayout(members_tab)

        self.members_list = QListWidget()
        self.members_list.setSelectionMode(QAbstractItemView.ExtendedSelection)

        member_button_row = QHBoxLayout()
        self.add_btn = QPushButton("Add...")
        self.remove_btn = QPushButton("Remove")
        self.apply_btn = QPushButton("Apply")
        member_button_row.addWidget(self.add_btn)
        member_button_row.addWidget(self.remove_btn)
        member_button_row.addStretch()
        member_button_row.addWidget(self.apply_btn)

        members_layout.addWidget(self.members_list)
        members_layout.addLayout(member_button_row)

        tabs.addTab(members_tab, "Members")

        member_of_tab = QWidget()
        member_of_layout = QVBoxLayout(member_of_tab)
        self.member_of_table = QTableWidget()
        self.member_of_table.setColumnCount(2)
        self.member_of_table.setHorizontalHeaderLabels(
            ["Name", "Active Directory Domain Services Folder"]
        )
        self.member_of_table.verticalHeader().setVisible(False)
        self.member_of_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.member_of_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.member_of_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        member_of_layout.addWidget(self.member_of_table)
        tabs.addTab(member_of_tab, "Member Of")

        managed_by_tab = QWidget()
        managed_by_layout = QFormLayout(managed_by_tab)
        self.managed_by_edit = QLineEdit(attrs.get("managedBy", [""])[0])
        managed_by_layout.addRow("Name:", self.managed_by_edit)
        tabs.addTab(managed_by_tab, "Managed By")

        object_tab = QWidget()
        object_layout = QFormLayout(object_tab)
        canonical_name = self.dn_to_canonical_name(group_obj.dn)
        created = attrs.get("whenCreated", [""])[0]
        modified = attrs.get("whenChanged", [""])[0]
        object_layout.addRow("Canonical name of object:", QLabel(canonical_name))
        object_layout.addRow("Object class:", QLabel("Group"))
        object_layout.addRow("Created:", QLabel(created))
        object_layout.addRow("Modified:", QLabel(modified))
        tabs.addTab(object_tab, "Object")
        tabs.addTab(self.build_attributes_tab(attrs), "Attribute Editor")

        self.security_editor = build_acl_viewer_tab(self.ldap, group_obj.dn, self.search_base, show_apply_button=False)
        self.security_editor.changed.connect(self.refresh_apply_button_state)
        tabs.addTab(self.security_editor, "Security")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.Apply)
        buttons.accepted.connect(self.on_ok)
        buttons.rejected.connect(self.reject)
        apply_button = buttons.button(QDialogButtonBox.Apply)
        if apply_button:
            self.apply_button = apply_button
            apply_button.clicked.connect(self.apply_changes)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

        self.add_btn.clicked.connect(self.add_members)
        self.remove_btn.clicked.connect(self.remove_selected_members)
        self.apply_btn.clicked.connect(self.apply_changes)

        self.load_members()
        self.load_member_of()

        self.sam_name_edit.textChanged.connect(self.refresh_apply_button_state)
        self.description_edit.textChanged.connect(self.refresh_apply_button_state)
        self.email_edit.textChanged.connect(self.refresh_apply_button_state)
        self.managed_by_edit.textChanged.connect(self.refresh_apply_button_state)
        self.members_list.model().rowsInserted.connect(lambda *_: self.refresh_apply_button_state())
        self.members_list.model().rowsRemoved.connect(lambda *_: self.refresh_apply_button_state())
        self.refresh_apply_button_state()

    def icon_for_object(self, obj: LdapObject) -> QIcon:
        return icon_for_directory_object(self.style(), obj)

    def dn_to_canonical_name(self, dn: str) -> str:
        parts = [part.strip() for part in dn.split(",") if part.strip()]
        dc_parts: list[str] = []
        path_parts: list[str] = []

        for part in reversed(parts):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key_upper = key.upper()
            if key_upper == "DC":
                dc_parts.append(value)
            elif key_upper in {"OU", "CN"}:
                path_parts.append(value)

        domain = ".".join(dc_parts)
        path = "/".join(path_parts)
        if domain and path:
            return f"{domain}/{path}"
        return domain or path or dn

    def load_members(self) -> None:
        members = self.ldap.get_group_members(self.group_obj.dn)
        self.members_list.clear()
        self.original_member_dns = [m.dn for m in members]
        for member in members:
            item = QListWidgetItem(f"{member.name} ({member.object_type})")
            item.setIcon(self.icon_for_object(member))
            item.setData(Qt.UserRole, member)
            item.setToolTip(member.dn)
            self.members_list.addItem(item)

    def load_member_of(self) -> None:
        groups = self.ldap.get_object_member_of(self.group_obj.dn)
        self.member_of_table.setRowCount(len(groups))

        for row, obj in enumerate(groups):
            name_item = QTableWidgetItem(obj.name)
            name_item.setIcon(self.icon_for_object(obj))
            dn_item = QTableWidgetItem(obj.dn)
            self.member_of_table.setItem(row, 0, name_item)
            self.member_of_table.setItem(row, 1, dn_item)

    def current_member_dns(self) -> list[str]:
        dns: list[str] = []
        for i in range(self.members_list.count()):
            item = self.members_list.item(i)
            obj = item.data(Qt.UserRole)
            if isinstance(obj, LdapObject):
                dns.append(obj.dn)
        return dns

    def add_members(self) -> None:
        dlg = SelectDirectoryObjectsDialog(self.ldap, self.search_base, self)
        if dlg.exec() != QDialog.Accepted:
            return

        existing_dns = set(self.current_member_dns())
        for obj in dlg.selected_objects():
            if obj.dn in existing_dns:
                continue
            item = QListWidgetItem(f"{obj.name} ({obj.object_type})")
            item.setData(Qt.UserRole, obj)
            item.setToolTip(obj.dn)
            self.members_list.addItem(item)
            existing_dns.add(obj.dn)

    def remove_selected_members(self) -> None:
        for item in self.members_list.selectedItems():
            row = self.members_list.row(item)
            self.members_list.takeItem(row)

    def has_pending_changes(self) -> bool:
        if self.sam_name_edit.text().strip() != self.original_sam_name:
            return True
        if self.description_edit.text().strip() != self.original_description:
            return True
        if self.email_edit.text().strip() != self.original_email:
            return True
        if self.managed_by_edit.text().strip() != self.original_managed_by:
            return True
        if self.current_member_dns() != self.original_member_dns:
            return True
        for attr_name in self.attribute_values:
            current_values = self.attribute_values.get(attr_name, [])
            original_values = self.original_attribute_values.get(attr_name, [])
            if current_values != original_values:
                return True
        if self.security_editor.has_pending_changes():
            return True
        return False

    def refresh_apply_button_state(self) -> None:
        if self.apply_button:
            self.apply_button.setEnabled(self.has_pending_changes())

    def apply_changes(self) -> bool:
        member_dns = self.current_member_dns()
        sam_name = self.sam_name_edit.text().strip()
        description = self.description_edit.text().strip()
        email = self.email_edit.text().strip()
        managed_by = self.managed_by_edit.text().strip()

        try:
            with busy_cursor():
                if sam_name != self.original_sam_name:
                    self.ldap.replace_object_attribute_values(self.group_obj.dn, "sAMAccountName", [sam_name] if sam_name else [])
                    self.original_sam_name = sam_name

                if description != self.original_description:
                    self.ldap.replace_object_attribute_values(self.group_obj.dn, "description", [description] if description else [])
                    self.original_description = description

                if email != self.original_email:
                    self.ldap.replace_object_attribute_values(self.group_obj.dn, "mail", [email] if email else [])
                    self.original_email = email

                if managed_by != self.original_managed_by:
                    self.ldap.replace_object_attribute_values(self.group_obj.dn, "managedBy", [managed_by] if managed_by else [])
                    self.original_managed_by = managed_by

                if member_dns != self.original_member_dns:
                    self.ldap.replace_group_members(self.group_obj.dn, member_dns)
                    self.original_member_dns = member_dns

                self.apply_attribute_changes()

                current_item = self.security_editor.principal_list.currentItem()
                selected_sid = str(current_item.data(Qt.UserRole)) if current_item else ""
                if not self.security_editor.apply_security_changes(reload_after_save=False):
                    return False
                self.security_editor.reload_from_directory(select_sid=selected_sid)
        except Exception as e:
            QMessageBox.critical(self, "Apply failed", str(e))
            return False

        self.refresh_apply_button_state()
        return True

    def on_ok(self) -> None:
        if self.apply_changes():
            self.accept()

    def build_attributes_tab(self, attrs: dict[str, list[str]]) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.show_empty_attributes_checkbox = QCheckBox("Show attributes with no values")
        self.show_empty_attributes_checkbox.setChecked(self.show_empty_attributes)
        self.show_empty_attributes_checkbox.toggled.connect(self.on_show_empty_attributes_toggled)
        layout.addWidget(self.show_empty_attributes_checkbox)

        editor_layout = QHBoxLayout()
        self.attributes_list = QListWidget()
        self.attributes_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.attributes_list.currentTextChanged.connect(self.on_attribute_selected)
        self.attributes_list.itemDoubleClicked.connect(self.on_attribute_double_clicked)

        right_col = QVBoxLayout()
        self.attribute_name_label = QLabel("Select an attribute")
        self.attribute_value_edit = QTextEdit()
        self.attribute_value_edit.setReadOnly(True)
        right_col.addWidget(self.attribute_name_label)
        right_col.addWidget(self.attribute_value_edit)

        editor_layout.addWidget(self.attributes_list, 1)
        editor_layout.addLayout(right_col, 2)
        layout.addLayout(editor_layout)

        self.refresh_attributes_list()
        return tab

    def _attribute_has_values(self, attr_name: str) -> bool:
        values = self.attribute_values.get(attr_name, [])
        return any(v.strip() for v in values)

    def refresh_attributes_list(self, preferred_attr: Optional[str] = None) -> None:
        current_attr = preferred_attr if preferred_attr is not None else self.attributes_list.currentItem().text() if self.attributes_list.currentItem() else ""
        visible_attrs = [
            attr_name
            for attr_name in sorted(self.attribute_values, key=str.lower)
            if self.show_empty_attributes or self._attribute_has_values(attr_name)
        ]
        self.attributes_list.blockSignals(True)
        self.attributes_list.clear()
        for attr_name in visible_attrs:
            self.attributes_list.addItem(attr_name)
        self.attributes_list.blockSignals(False)

        if not visible_attrs:
            self.selected_attribute = None
            self.on_attribute_selected("")
            return

        target_attr = current_attr if current_attr in visible_attrs else visible_attrs[0]
        for idx in range(self.attributes_list.count()):
            if self.attributes_list.item(idx).text() == target_attr:
                self.attributes_list.setCurrentRow(idx)
                break
        self.on_attribute_selected(target_attr)

    def on_show_empty_attributes_toggled(self, checked: bool) -> None:
        self.show_empty_attributes = checked
        if callable(self.on_toggle_show_empty_attributes):
            self.on_toggle_show_empty_attributes(checked)
        self.refresh_attributes_list()

    def on_attribute_selected(self, attr_name: str) -> None:
        self.selected_attribute = attr_name if attr_name else None
        if not self.attribute_name_label or not self.attribute_value_edit:
            return

        if not attr_name:
            self.attribute_name_label.setText("Select an attribute")
            self.attribute_value_edit.clear()
            return

        values = self.attribute_values.get(attr_name, [])
        is_read_only = attr_name in self.NON_EDITABLE_ATTRIBUTES
        status = "(read-only)" if is_read_only else "(double-click to edit)"
        self.attribute_name_label.setText(f"{attr_name} {status}")
        self.attribute_value_edit.setPlainText("\n".join(values))

    def _is_attribute_integer(self, attr_name: str, values: list[str]) -> bool:
        schema_info = self.ldap.get_attribute_schema_info(attr_name)
        if schema_info.get("is_integer") is True:
            return True
        if schema_info.get("is_integer") is False:
            return False
        if not values:
            return False
        try:
            int(values[0])
            return True
        except ValueError:
            return False

    def _is_attribute_multi_valued(self, attr_name: str, values: list[str]) -> bool:
        schema_info = self.ldap.get_attribute_schema_info(attr_name)
        if schema_info.get("single_valued") is False:
            return True
        if schema_info.get("single_valued") is True:
            return False
        return len(values) > 1 or attr_name.lower() in {"serviceprincipalname"}

    def on_attribute_double_clicked(self, item: QListWidgetItem) -> None:
        attr_name = item.text().strip()
        if not attr_name or attr_name in self.NON_EDITABLE_ATTRIBUTES:
            return

        current_values = list(self.attribute_values.get(attr_name, []))
        if self._is_attribute_multi_valued(attr_name, current_values):
            editor = MultiValuedStringEditorDialog(attr_name, current_values, self)
            if editor.exec() != QDialog.Accepted:
                return
            new_values = editor.edited_values()
        else:
            is_integer = self._is_attribute_integer(attr_name, current_values)
            title = "Integer Attribute Editor" if is_integer else "String Attribute Editor"
            editor = SingleValueAttributeEditorDialog(title, current_values[0] if current_values else "", self)
            if editor.exec() != QDialog.Accepted:
                return
            new_value = editor.edited_value()
            if is_integer and new_value:
                try:
                    int(new_value)
                except ValueError:
                    QMessageBox.warning(self, "Invalid value", "Please enter a valid integer value.")
                    return
            new_values = [new_value] if new_value else []

        self.attribute_values[attr_name] = new_values
        self.refresh_attributes_list(preferred_attr=attr_name)
        self.refresh_apply_button_state()

    def apply_attribute_changes(self) -> None:
        for attr_name in sorted(self.attribute_values):
            if attr_name in self.NON_EDITABLE_ATTRIBUTES:
                continue
            current_values = self.attribute_values.get(attr_name, [])
            original_values = self.original_attribute_values.get(attr_name, [])
            if current_values == original_values:
                continue
            self.ldap.replace_object_attribute_values(self.group_obj.dn, attr_name, current_values)
            self.original_attribute_values[attr_name] = list(current_values)


class DirectoryTableWidget(QTableWidget):
    group_membership_drop = Signal(object, list)

    DRAG_MIME_TYPE = "application/x-aduc-directory-objects"

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDefaultDropAction(Qt.CopyAction)
        self.setDragDropMode(QAbstractItemView.DragDrop)

    def startDrag(self, supported_actions) -> None:
        selected_rows = sorted({idx.row() for idx in self.selectionModel().selectedRows()})
        payload: list[dict[str, str]] = []
        for row in selected_rows:
            item = self.item(row, 0)
            if not item:
                continue
            obj = item.data(Qt.UserRole)
            if not isinstance(obj, LdapObject):
                continue
            payload.append({"dn": obj.dn, "type": obj.object_type})

        if not payload:
            return

        drag = QDrag(self)
        mime = QMimeData()
        mime.setData(self.DRAG_MIME_TYPE, json.dumps(payload).encode("utf-8"))
        drag.setMimeData(mime)
        drag.exec(Qt.CopyAction)

    def dragEnterEvent(self, event) -> None:
        if self._can_accept_drop(event):
            event.acceptProposedAction()
            return
        event.ignore()

    def dragMoveEvent(self, event) -> None:
        if self._can_accept_drop(event):
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event) -> None:
        if not self._can_accept_drop(event):
            event.ignore()
            return

        item = self.itemAt(event.position().toPoint())
        if not item:
            event.ignore()
            return

        target_name_item = self.item(item.row(), 0)
        if not target_name_item:
            event.ignore()
            return

        target_obj = target_name_item.data(Qt.UserRole)
        if not isinstance(target_obj, LdapObject) or target_obj.object_type != "Group":
            event.ignore()
            return

        payload = self._decode_drop_payload(event)
        if not payload:
            event.ignore()
            return

        self.group_membership_drop.emit(target_obj, payload)
        event.acceptProposedAction()

    def _can_accept_drop(self, event) -> bool:
        item = self.itemAt(event.position().toPoint())
        if not item:
            return False

        target_name_item = self.item(item.row(), 0)
        if not target_name_item:
            return False

        target_obj = target_name_item.data(Qt.UserRole)
        if not isinstance(target_obj, LdapObject):
            return False
        if target_obj.object_type != "Group":
            return False

        payload = self._decode_drop_payload(event)
        return bool(payload)

    def _decode_drop_payload(self, event) -> list[dict[str, str]]:
        mime = event.mimeData()
        if not mime or not mime.hasFormat(self.DRAG_MIME_TYPE):
            return []

        try:
            raw = bytes(mime.data(self.DRAG_MIME_TYPE))
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            return []

        decoded: list[dict[str, str]] = []
        if not isinstance(parsed, list):
            return decoded

        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            dn = str(entry.get("dn", "")).strip()
            obj_type = str(entry.get("type", "")).strip()
            if not dn:
                continue
            decoded.append({"dn": dn, "type": obj_type})
        return decoded


class DirectoryTreeWidget(QTreeWidget):
    directory_move_drop = Signal(str, list)

    DRAG_MIME_TYPE = DirectoryTableWidget.DRAG_MIME_TYPE

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self._hover_drop_item: Optional[QTreeWidgetItem] = None

    def _set_hover_drop_item(self, item: Optional[QTreeWidgetItem]) -> None:
        if self._hover_drop_item is item:
            return

        if self._hover_drop_item is not None:
            self._hover_drop_item.setBackground(0, QBrush())

        self._hover_drop_item = item

        if self._hover_drop_item is not None:
            self._hover_drop_item.setBackground(0, QBrush(QColor("#CFE8FF")))

    def dragEnterEvent(self, event) -> None:
        if self._can_accept_drop(event):
            item = self.itemAt(event.position().toPoint())
            self._set_hover_drop_item(item)
            event.acceptProposedAction()
            return
        self._set_hover_drop_item(None)
        event.ignore()

    def dragMoveEvent(self, event) -> None:
        if self._can_accept_drop(event):
            item = self.itemAt(event.position().toPoint())
            self._set_hover_drop_item(item)
            event.acceptProposedAction()
            return
        self._set_hover_drop_item(None)
        event.ignore()

    def dragLeaveEvent(self, event) -> None:
        self._set_hover_drop_item(None)
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:
        if not self._can_accept_drop(event):
            self._set_hover_drop_item(None)
            event.ignore()
            return

        item = self.itemAt(event.position().toPoint())
        if not item:
            self._set_hover_drop_item(None)
            event.ignore()
            return

        data = item.data(0, Qt.UserRole) or {}
        target_dn = str(data.get("dn", "")).strip()
        if not target_dn or not bool(data.get("container", False)):
            event.ignore()
            return

        payload = self._decode_drop_payload(event)
        if not payload:
            self._set_hover_drop_item(None)
            event.ignore()
            return

        self.directory_move_drop.emit(target_dn, payload)
        self._set_hover_drop_item(None)
        event.acceptProposedAction()

    def _can_accept_drop(self, event) -> bool:
        item = self.itemAt(event.position().toPoint())
        if not item:
            return False

        data = item.data(0, Qt.UserRole) or {}
        if not bool(data.get("container", False)):
            return False

        payload = self._decode_drop_payload(event)
        return bool(payload)

    def _decode_drop_payload(self, event) -> list[dict[str, str]]:
        mime = event.mimeData()
        if not mime or not mime.hasFormat(self.DRAG_MIME_TYPE):
            return []

        try:
            raw = bytes(mime.data(self.DRAG_MIME_TYPE))
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            return []

        decoded: list[dict[str, str]] = []
        if not isinstance(parsed, list):
            return decoded

        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            dn = str(entry.get("dn", "")).strip()
            obj_type = str(entry.get("type", "")).strip()
            if not dn:
                continue
            decoded.append({"dn": dn, "type": obj_type})
        return decoded


class MoveObjectDialog(QDialog):
    def __init__(self, ldap: LdapManager, title: str, parent=None) -> None:
        super().__init__(parent)
        self.ldap = ldap
        self.setWindowTitle(title)
        self.resize(520, 520)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Move object to")
        self.tree.setExpandsOnDoubleClick(True)
        self.tree.itemExpanded.connect(self.on_item_expanded)
        self.tree.currentItemChanged.connect(self.on_current_item_changed)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.ok_button = self.buttons.button(QDialogButtonBox.Ok)
        if self.ok_button is not None:
            self.ok_button.setEnabled(False)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.tree)
        layout.addWidget(self.buttons)

        self.populate_roots()

    def populate_roots(self) -> None:
        self.tree.clear()
        try:
            contexts = self.ldap.get_naming_contexts()
        except Exception:
            contexts = []

        if not contexts:
            default_context = self.ldap.get_default_naming_context()
            if default_context:
                contexts = [default_context]

        for dn in contexts:
            item = QTreeWidgetItem([dn])
            item.setData(
                0,
                Qt.UserRole,
                {
                    "dn": dn,
                    "loaded": False,
                    "container": False,
                    "object_classes": ["domain"],
                },
            )
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            item.setIcon(0, icon_for_object_classes(self.style(), ["domain"], has_child_ou=True))
            self.tree.addTopLevelItem(item)
            self.load_tree_children(item)
            item.setExpanded(True)

    def load_tree_children(self, item: QTreeWidgetItem) -> None:
        data = item.data(0, Qt.UserRole) or {}
        if data.get("loaded", False):
            return

        dn = str(data.get("dn", "")).strip()
        if not dn:
            return

        try:
            children = self.ldap.list_children(dn)
        except Exception:
            children = []

        while item.childCount():
            item.takeChild(0)

        for child in children:
            if not child.is_container:
                continue
            child_item = QTreeWidgetItem([child.name])
            child_item.setData(
                0,
                Qt.UserRole,
                {
                    "dn": child.dn,
                    "loaded": False,
                    "container": True,
                    "object_classes": child.object_classes,
                },
            )
            child_item.setIcon(0, icon_for_directory_object(self.style(), child))
            child_item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            item.addChild(child_item)

        data["loaded"] = True
        item.setData(0, Qt.UserRole, data)

    def on_item_expanded(self, item: QTreeWidgetItem) -> None:
        self.load_tree_children(item)

    def on_current_item_changed(self, current: Optional[QTreeWidgetItem], _previous: Optional[QTreeWidgetItem]) -> None:
        can_accept = False
        if current is not None:
            data = current.data(0, Qt.UserRole) or {}
            object_classes = {str(cls).lower() for cls in data.get("object_classes", [])}
            can_accept = bool({"organizationalunit", "container", "builtindomain"} & object_classes)

        if self.ok_button is not None:
            self.ok_button.setEnabled(can_accept)

    def selected_target_dn(self) -> Optional[str]:
        item = self.tree.currentItem()
        if not item:
            return None

        data = item.data(0, Qt.UserRole) or {}
        object_classes = {str(cls).lower() for cls in data.get("object_classes", [])}
        if not ({"organizationalunit", "container", "builtindomain"} & object_classes):
            return None

        dn = str(data.get("dn", "")).strip()
        return dn or None


class MoveOperationWorker(QObject):
    progress = Signal(int, int, str)
    finished = Signal(int, list)

    def __init__(
        self,
        auth_mode: str,
        host: str,
        port: int,
        bind_user: str,
        bind_password: str,
        objects: list[LdapObject],
        target_dn: str,
    ) -> None:
        super().__init__()
        self.auth_mode = auth_mode
        self.host = host
        self.port = port
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.objects = objects
        self.target_dn = target_dn

    def run(self) -> None:
        failures: list[str] = []
        moved_count = 0
        normalized_target = self.target_dn.strip().lower()
        ldap = LdapManager()

        try:
            if self.auth_mode == "kerberos":
                ldap.connect_kerberos(self.host, port=self.port)
            else:
                ldap.connect_simple(self.host, self.bind_user, self.bind_password, port=self.port)
        except Exception as e:
            self.finished.emit(0, [f"Unable to connect for move operation: {e}"])
            return

        try:
            for index, obj in enumerate(self.objects, start=1):
                self.progress.emit(index, len(self.objects), obj.name)

                current_parent = ldap.parent_dn(obj.dn)
                if not current_parent:
                    failures.append(f"{obj.name}: object has no movable parent")
                    continue
                if current_parent.lower() == normalized_target:
                    continue
                if obj.dn.strip().lower() == normalized_target:
                    failures.append(f"{obj.name}: cannot move an object into itself")
                    continue
                if normalized_target.endswith("," + obj.dn.strip().lower()):
                    failures.append(f"{obj.name}: cannot move an object into its own subtree")
                    continue

                try:
                    ldap.move_object(obj.dn, self.target_dn)
                    moved_count += 1
                except Exception as e:
                    failures.append(f"{obj.dn}: {e}")
        finally:
            if ldap.conn:
                try:
                    ldap.conn.unbind()
                except Exception:
                    pass

        self.finished.emit(moved_count, failures)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ADUC for Linux")
        self.setWindowIcon(build_application_icon())
        self.resize(1400, 800)

        self.ldap = LdapManager()
        self.auth_mode = "credentials"
        self.saved_host = ""
        self.saved_port = 636
        self.auto_connect = False
        self.connection_profiles: list[ConnectionProfile] = []
        self.active_profile_name = ""
        self.last_bind_user = ""
        self.last_bind_password = ""
        self.connection_alert_shown = False
        self.main_table_column_widths: list[int] = []
        self.window_size: Optional[tuple[int, int]] = None
        self.main_splitter_sizes: list[int] = []
        self.show_advanced_features = True
        self.show_empty_attributes = False
        self.current_dn: Optional[str] = None
        self.pending_auto_connect = False
        self._move_thread: Optional[QThread] = None
        self._move_worker: Optional[MoveOperationWorker] = None
        self._move_progress_dialog: Optional[QProgressDialog] = None
        self.load_settings()

        if self.window_size:
            self.resize(*self.window_size)

        self.tree = DirectoryTreeWidget()
        self.tree.setHeaderLabel("Active Directory")
        self.tree.setExpandsOnDoubleClick(False)
        self.tree.itemClicked.connect(self.on_tree_clicked)
        self.tree.itemDoubleClicked.connect(self.on_tree_double_clicked)
        self.tree.itemExpanded.connect(self.on_tree_expanded)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_tree_context_menu)

        self.table = DirectoryTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Type", "Description", "Distinguished Name"])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.cellDoubleClicked.connect(self.on_table_double_clicked)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.on_table_context_menu)
        self.table.group_membership_drop.connect(self.on_group_membership_drop)
        self.tree.directory_move_drop.connect(self.on_directory_move_drop)
        self.table.itemSelectionChanged.connect(self.update_status_bar)

        self.apply_saved_main_table_widths()

        self.splitter = QSplitter()
        self.splitter.addWidget(self.tree)
        self.splitter.addWidget(self.table)
        self.splitter.setStretchFactor(1, 1)
        self.apply_saved_splitter_sizes()

        central = QWidget()
        root_layout = QVBoxLayout(central)

        root_layout.addWidget(self.splitter, 1)

        self.setCentralWidget(central)

        file_menu = self.menuBar().addMenu("File")

        connect_action = QAction("Connect", self)
        connect_action.triggered.connect(self.show_connect_dialog)
        file_menu.addAction(connect_action)

        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_current)
        file_menu.addAction(refresh_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        action_menu = self.menuBar().addMenu("Action")

        self.find_action = QAction("Find...", self)
        self.find_action.setShortcut("Ctrl+F")
        self.find_action.triggered.connect(self.find_in_current)
        action_menu.addAction(self.find_action)

        self.properties_action = QAction("Properties", self)
        self.properties_action.setShortcut("Alt+Return")
        self.properties_action.triggered.connect(self.open_selected_properties)
        action_menu.addAction(self.properties_action)

        self.rename_action = QAction("Rename", self)
        self.rename_action.setShortcut("F2")
        self.rename_action.triggered.connect(self.rename_selected_object)
        action_menu.addAction(self.rename_action)

        self.delete_action = QAction("Delete", self)
        self.delete_action.setShortcut("Delete")
        self.delete_action.triggered.connect(self.delete_selected_objects)
        action_menu.addAction(self.delete_action)

        action_menu.addSeparator()
        self.new_user_action = QAction("New User...", self)
        self.new_user_action.triggered.connect(self.create_user_in_current)
        action_menu.addAction(self.new_user_action)

        self.new_group_action = QAction("New Group...", self)
        self.new_group_action.triggered.connect(self.create_group_in_current)
        action_menu.addAction(self.new_group_action)

        self.new_computer_action = QAction("New Computer...", self)
        self.new_computer_action.triggered.connect(self.create_computer_in_current)
        action_menu.addAction(self.new_computer_action)

        self.new_ou_action = QAction("New Organizational Unit...", self)
        self.new_ou_action.triggered.connect(self.create_ou_in_current)
        action_menu.addAction(self.new_ou_action)

        view_menu = self.menuBar().addMenu("View")
        refresh_action.setShortcut("F5")
        view_menu.addAction(refresh_action)

        self.advanced_features_action = QAction("Advanced Features", self)
        self.advanced_features_action.setCheckable(True)
        self.advanced_features_action.setChecked(self.show_advanced_features)
        self.advanced_features_action.triggered.connect(self.toggle_advanced_features)
        view_menu.addAction(self.advanced_features_action)

        help_menu = self.menuBar().addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        self.refresh_advanced_features_ui()
        self.update_status_bar()

        if self.auto_connect and self.saved_host:
            self.pending_auto_connect = True

    def center_dialog_over_main_window(self, dialog: QDialog) -> None:
        if not self.isVisible():
            return

        dialog.adjustSize()

        main_window = self.window()
        window_center_global = main_window.frameGeometry().center()

        main_window_handle = main_window.windowHandle()
        screen = main_window_handle.screen() if main_window_handle is not None else None
        if screen is None:
            screen = QApplication.screenAt(window_center_global)
        if screen is None:
            screen = self.screen() or QApplication.primaryScreen()

        dialog_window = dialog.windowHandle()
        if dialog_window is not None:
            if main_window_handle is not None:
                dialog_window.setTransientParent(main_window_handle)

        dialog_rect = dialog.frameGeometry()
        dialog_rect.moveCenter(window_center_global)
        top_left = dialog_rect.topLeft()

        if screen is not None:
            available = screen.availableGeometry()
            x = max(available.left(), min(top_left.x(), available.right() - dialog_rect.width() + 1))
            y = max(available.top(), min(top_left.y(), available.bottom() - dialog_rect.height() + 1))
            top_left = QPoint(x, y)

        dialog.move(top_left)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self.pending_auto_connect:
            self.pending_auto_connect = False
            QTimer.singleShot(0, self.auto_connect_if_configured)

    def icon_for_object(self, obj: LdapObject) -> QIcon:
        return icon_for_directory_object(self.style(), obj)

    def show_error(self, title: str, message: str) -> None:
        QMessageBox.critical(self, title, message)

    @staticmethod
    def is_connection_error(error: Exception) -> bool:
        text = str(error).lower()
        connection_markers = [
            "socket",
            "connection",
            "eof occurred",
            "session terminated",
            "broken pipe",
            "server down",
            "timed out",
            "connection reset",
            "can't contact ldap server",
        ]
        return any(marker in text for marker in connection_markers)

    def can_attempt_reconnect(self) -> bool:
        if not self.saved_host:
            return False
        if self.auth_mode == "kerberos":
            return True
        return bool(self.last_bind_user and self.last_bind_password)

    def reset_connection_alert(self) -> None:
        self.connection_alert_shown = False

    def show_connection_alert_once(self, message: str) -> None:
        self.statusBar().showMessage(message)
        if self.connection_alert_shown:
            return
        self.connection_alert_shown = True
        self.show_error("Connection issue", message)

    def reconnect(self) -> None:
        if self.auth_mode == "kerberos":
            self.ldap.connect_kerberos(self.saved_host, port=self.saved_port)
        else:
            self.ldap.connect_simple(
                self.saved_host,
                self.last_bind_user,
                self.last_bind_password,
                port=self.saved_port,
            )
        self.reset_connection_alert()

    def with_connection_retry(self, action, reconnect_message: str):
        try:
            return action()
        except Exception as first_error:
            if not self.is_connection_error(first_error) or not self.can_attempt_reconnect():
                raise

        try:
            self.reconnect()
            return action()
        except Exception:
            self.show_connection_alert_once(reconnect_message)
            return None

    def show_about_dialog(self) -> None:
        QMessageBox.information(
            self,
            "About ADUC for Linux",
            "ADUC for Linux\n\n"
            "A Linux-friendly Active Directory Users and Computers-style management console.",
        )

    def update_status_bar(self) -> None:
        selected_rows = len(self.table.selectionModel().selectedRows()) if self.table.selectionModel() else 0
        object_count = self.table.rowCount()
        location = self.current_dn or "No container selected"
        self.statusBar().showMessage(
            f"Objects: {object_count} | Selected: {selected_rows} | Location: {location}"
        )

    def refresh_advanced_features_ui(self) -> None:
        # ADUC typically exposes additional DN/object details in advanced mode.
        self.table.setColumnHidden(3, not self.show_advanced_features)

    def toggle_advanced_features(self, checked: bool) -> None:
        self.show_advanced_features = checked
        self.refresh_advanced_features_ui()
        self.update_status_bar()

    @contextmanager
    def busy_cursor(self):
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            yield
        finally:
            QApplication.restoreOverrideCursor()

    def load_settings(self) -> None:
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except Exception:
            return

        self.auth_mode = str(data.get("auth_mode", "credentials"))
        self.saved_host = str(data.get("host", ""))
        self.saved_port = int(data.get("port", 636))
        self.auto_connect = bool(data.get("auto_connect", False))
        self.active_profile_name = str(data.get("active_profile", ""))
        self.show_advanced_features = bool(data.get("show_advanced_features", True))
        self.show_empty_attributes = bool(data.get("show_empty_attributes", False))

        self.connection_profiles = []
        profile_items = data.get("connection_profiles", [])
        if isinstance(profile_items, list):
            for profile in profile_items:
                if not isinstance(profile, dict):
                    continue
                name = str(profile.get("name", "")).strip()
                host = str(profile.get("host", "")).strip()
                if not name or not host:
                    continue
                try:
                    port = int(profile.get("port", 636))
                except (TypeError, ValueError):
                    port = 636
                auth_mode = str(profile.get("auth_mode", "credentials"))
                bind_user = str(profile.get("bind_user", ""))
                store_password = bool(profile.get("store_password", False))
                self.connection_profiles.append(
                    ConnectionProfile(
                        name=name,
                        host=host,
                        port=port,
                        auth_mode=auth_mode,
                        bind_user=bind_user,
                        store_password=store_password,
                    )
                )

        active_profile = self.find_connection_profile(self.active_profile_name)
        if active_profile is not None:
            self.auth_mode = active_profile.auth_mode
            self.saved_host = active_profile.host
            self.saved_port = active_profile.port

        widths = data.get("main_table_column_widths", [])
        if isinstance(widths, list):
            parsed_widths: list[int] = []
            for width in widths:
                try:
                    parsed_widths.append(int(width))
                except (TypeError, ValueError):
                    continue
            self.main_table_column_widths = parsed_widths

        try:
            width = int(data.get("window_width", 0))
            height = int(data.get("window_height", 0))
            if width > 0 and height > 0:
                self.window_size = (width, height)
        except (TypeError, ValueError):
            self.window_size = None

        splitter_sizes = data.get("main_splitter_sizes", [])
        if isinstance(splitter_sizes, list):
            parsed_splitter_sizes: list[int] = []
            for size in splitter_sizes:
                try:
                    parsed_splitter_sizes.append(int(size))
                except (TypeError, ValueError):
                    continue
            self.main_splitter_sizes = parsed_splitter_sizes

    def save_settings(self) -> None:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        data = {
            "auth_mode": self.auth_mode,
            "host": self.saved_host,
            "port": self.saved_port,
            "auto_connect": self.auto_connect,
            "show_advanced_features": self.show_advanced_features,
            "show_empty_attributes": self.show_empty_attributes,
            "active_profile": self.active_profile_name,
            "connection_profiles": [
                {
                    "name": profile.name,
                    "host": profile.host,
                    "port": profile.port,
                    "auth_mode": profile.auth_mode,
                    "bind_user": profile.bind_user,
                    "store_password": profile.store_password,
                }
                for profile in self.connection_profiles
            ],
            "main_table_column_widths": [self.table.columnWidth(i) for i in range(self.table.columnCount())],
            "window_width": self.width(),
            "window_height": self.height(),
            "main_splitter_sizes": self.splitter.sizes(),
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def find_connection_profile(self, profile_name: str) -> Optional[ConnectionProfile]:
        target = profile_name.strip()
        if not target:
            return None
        for profile in self.connection_profiles:
            if profile.name == target:
                return profile
        return None

    def set_show_empty_attributes_preference(self, enabled: bool) -> None:
        enabled_bool = bool(enabled)
        if self.show_empty_attributes == enabled_bool:
            return
        self.show_empty_attributes = enabled_bool
        self.save_settings()

    def delete_connection_profiles(self, profile_names: list[str]) -> None:
        targets = {name.strip() for name in profile_names if name.strip()}
        if not targets:
            return

        self.connection_profiles = [profile for profile in self.connection_profiles if profile.name not in targets]
        for name in targets:
            CredentialStore.delete_password(name)

        if self.active_profile_name in targets:
            self.active_profile_name = ""

    def apply_saved_main_table_widths(self) -> None:
        if not self.main_table_column_widths:
            return

        for index, width in enumerate(self.main_table_column_widths):
            if index >= self.table.columnCount() or width <= 0:
                continue
            self.table.setColumnWidth(index, width)

    def apply_saved_splitter_sizes(self) -> None:
        if len(self.main_splitter_sizes) < 2:
            return

        if any(size <= 0 for size in self.main_splitter_sizes[:2]):
            return

        self.splitter.setSizes(self.main_splitter_sizes)

    def closeEvent(self, event) -> None:
        self.save_settings()
        super().closeEvent(event)

    def auto_connect_if_configured(self) -> None:
        if not self.saved_host:
            return

        try:
            def connect_and_load() -> None:
                if self.auth_mode == "kerberos":
                    self.ldap.connect_kerberos(self.saved_host, port=self.saved_port)
                    self.last_bind_user = ""
                    self.last_bind_password = ""
                else:
                    bind_user = self.last_bind_user
                    bind_password = self.last_bind_password
                    if self.active_profile_name:
                        profile = self.find_connection_profile(self.active_profile_name)
                        if profile is not None:
                            bind_user = profile.bind_user
                            if profile.store_password:
                                bind_password = CredentialStore.get_password(profile.name)
                    if not bind_user or not bind_password:
                        raise ValueError("Saved credentials are not available for auto-connect.")
                    self.ldap.connect_simple(self.saved_host, bind_user, bind_password, port=self.saved_port)
                    self.last_bind_user = bind_user
                    self.last_bind_password = bind_password
                self.reset_connection_alert()

                self.populate_roots()

            with self.busy_cursor():
                connect_and_load()
        except Exception as e:
            self.show_error("Auto-connect failed", str(e))
            return

    def show_connect_dialog(self) -> None:
        dlg = ConnectDialog(
            self.auth_mode,
            self.saved_host,
            self.saved_port,
            profiles=self.connection_profiles,
            selected_profile=self.active_profile_name,
            auto_connect=self.auto_connect,
            parent=self,
        )
        result = dlg.exec()
        deleted_profiles = dlg.deleted_profiles()
        if deleted_profiles:
            self.delete_connection_profiles(deleted_profiles)
            self.save_settings()

        if result != QDialog.Accepted:
            return

        host, port, bind_user, password = dlg.values()
        self.auth_mode = dlg.selected_auth_mode()
        self.auto_connect = dlg.selected_auto_connect()

        try:
            if self.auth_mode == "kerberos":
                self.ldap.connect_kerberos(host, port=port)
                self.last_bind_user = ""
                self.last_bind_password = ""
            else:
                self.ldap.connect_simple(host, bind_user, password, port=port)
                self.last_bind_user = bind_user
                self.last_bind_password = password
        except Exception as e:
            self.show_error("Connection failed", str(e))
            return

        self.saved_host = host
        self.saved_port = port

        if dlg.save_profile_enabled():
            profile_name = dlg.selected_profile_name()
            if profile_name:
                existing = self.find_connection_profile(profile_name)
                if existing is None:
                    self.connection_profiles.append(
                        ConnectionProfile(
                            name=profile_name,
                            host=host,
                            port=port,
                            auth_mode=self.auth_mode,
                            bind_user=bind_user,
                            store_password=dlg.save_password_enabled(),
                        )
                    )
                    existing = self.connection_profiles[-1]
                else:
                    existing.host = host
                    existing.port = port
                    existing.auth_mode = self.auth_mode
                    existing.bind_user = bind_user
                    existing.store_password = dlg.save_password_enabled()

                self.active_profile_name = profile_name
                if dlg.save_password_enabled():
                    if not CredentialStore.set_password(profile_name, password):
                        existing.store_password = False
                        QMessageBox.warning(
                            self,
                            "Credential storage unavailable",
                            "Connected successfully, but credentials could not be saved to the system keyring.",
                        )
                else:
                    CredentialStore.delete_password(profile_name)

        self.reset_connection_alert()
        self.save_settings()
        self.populate_roots()

    def populate_roots(self) -> None:
        self.tree.clear()
        self.table.setRowCount(0)
        self.current_dn = None

        partitions = self.with_connection_retry(
            self.ldap.get_directory_partitions,
            "Connection to the domain controller was lost. Please reconnect.",
        )
        if partitions is None:
            return

        default_nc = partitions.get("default_naming_context")
        root_domain_nc = partitions.get("root_domain_naming_context")
        domain_ncs = partitions.get("domain_naming_contexts", [])

        ordered_roots: list[tuple[str, str]] = []

        if root_domain_nc:
            label = f"{root_domain_nc} (Forest Root)"
            ordered_roots.append((label, root_domain_nc))

        if default_nc and default_nc != root_domain_nc:
            label = f"{default_nc} (Current Domain)"
            ordered_roots.append((label, default_nc))

        for dn in domain_ncs:
            if any(existing_dn == dn for _, existing_dn in ordered_roots):
                continue
            ordered_roots.append((dn, dn))

        for label, dn in ordered_roots:
            item = QTreeWidgetItem([label])
            item.setData(0, Qt.UserRole, {"dn": dn, "loaded": False, "container": True})
            item.setIcon(0, self.style().standardIcon(QStyle.SP_DirHomeIcon))
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            self.tree.addTopLevelItem(item)

        trusted_domains: list[dict[str, str]] = []
        if default_nc:
            try:
                trusted_domains = self.ldap.get_trusted_domains(default_nc)
            except Exception:
                trusted_domains = []

        if trusted_domains:
            trusted_root = QTreeWidgetItem(["Trusted Domains"])
            trusted_root.setData(0, Qt.UserRole, {"dn": None, "loaded": True, "container": False})
            trusted_root.setIcon(0, self.style().standardIcon(QStyle.SP_DirIcon))
            self.tree.addTopLevelItem(trusted_root)

            known_domains = set(domain_ncs)
            for trusted in trusted_domains:
                partner = trusted.get("partner", "")
                flat_name = trusted.get("flat_name", "")
                text = partner
                if flat_name:
                    text = f"{partner} ({flat_name})"

                browse_dn = ""
                if partner:
                    candidate_dn = ",".join(f"DC={part}" for part in partner.split(".") if part)
                    if candidate_dn in known_domains:
                        browse_dn = candidate_dn

                child_item = QTreeWidgetItem([text])
                child_item.setIcon(0, self.style().standardIcon(QStyle.SP_DirLinkIcon))
                if browse_dn:
                    child_item.setData(0, Qt.UserRole, {"dn": browse_dn, "loaded": False, "container": True})
                    child_item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                else:
                    child_item.setData(0, Qt.UserRole, {"dn": None, "loaded": True, "container": False})
                trusted_root.addChild(child_item)

            trusted_root.setExpanded(True)

        if not ordered_roots and not trusted_domains:
            contexts = self.ldap.get_naming_contexts()
            for dn in contexts:
                item = QTreeWidgetItem([dn])
                item.setData(0, Qt.UserRole, {"dn": dn, "loaded": False, "container": True})
                item.setIcon(0, self.style().standardIcon(QStyle.SP_DirHomeIcon))
                item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                self.tree.addTopLevelItem(item)

        for index in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(index).setExpanded(True)
        self.update_status_bar()

    def load_tree_children(self, item: QTreeWidgetItem) -> None:
        data = item.data(0, Qt.UserRole) or {}
        if data.get("loaded"):
            return

        dn = data.get("dn")
        if not dn:
            return

        try:
            children = self.with_connection_retry(
                lambda: self.ldap.list_children(dn),
                "Connection to the domain controller was lost. Please reconnect.",
            )
            if children is None:
                return
        except Exception as e:
            self.show_error("Browse failed", str(e))
            return

        for child in children:
            if not child.is_container:
                continue

            child_item = QTreeWidgetItem([child.name])
            child_item.setData(
                0,
                Qt.UserRole,
                {"dn": child.dn, "loaded": False, "container": child.is_container},
            )
            child_item.setIcon(0, self.icon_for_object(child))
            if child.is_container:
                child_item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            item.addChild(child_item)

        data["loaded"] = True
        item.setData(0, Qt.UserRole, data)

    def populate_main_pane(self, dn: str, add_history: bool = True) -> None:
        try:
            children = self.with_connection_retry(
                lambda: self.ldap.list_children(dn),
                "Connection to the domain controller was lost. Please reconnect.",
            )
            if children is None:
                return
        except Exception as e:
            self.show_error("List failed", str(e))
            return

        self.current_dn = dn

        self.table.setRowCount(len(children))

        for row, obj in enumerate(children):
            name_item = QTableWidgetItem(obj.name)
            name_item.setIcon(self.icon_for_object(obj))
            name_item.setData(Qt.UserRole, obj)
            name_item.setToolTip(obj.name)

            type_item = QTableWidgetItem(obj.object_type)
            desc_item = QTableWidgetItem(obj.description)
            dn_item = QTableWidgetItem(obj.dn)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, type_item)
            self.table.setItem(row, 2, desc_item)
            self.table.setItem(row, 3, dn_item)
        self.update_status_bar()

    def populate_search_results(self, results: list[LdapObject]) -> None:
        self.table.setRowCount(len(results))

        for row, obj in enumerate(results):
            name_item = QTableWidgetItem(obj.name)
            name_item.setIcon(self.icon_for_object(obj))
            name_item.setData(Qt.UserRole, obj)
            name_item.setToolTip(obj.name)

            type_item = QTableWidgetItem(obj.object_type)
            desc_item = QTableWidgetItem(obj.description)
            dn_item = QTableWidgetItem(obj.dn)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, type_item)
            self.table.setItem(row, 2, desc_item)
            self.table.setItem(row, 3, dn_item)


    def run_search(
        self,
        base_dn: str,
        term: str,
        search_mode: str = SEARCH_FILTER_USERS_CONTACTS_GROUPS,
    ) -> None:
        if not term:
            return

        try:
            results = self.ldap.search_objects(base_dn, term, search_mode=search_mode)
        except Exception as e:
            self.show_error("Search failed", str(e))
            return

        self.table.clearContents()
        self.populate_search_results(results)
        self.update_status_bar()

    def open_properties(self, obj: LdapObject) -> None:
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            attrs = self.ldap.get_object_attributes(obj.dn)

            search_base = self.current_dn
            if not search_base:
                top = self.tree.topLevelItem(0)
                if top:
                    data = top.data(0, Qt.UserRole) or {}
                    search_base = data.get("dn")

            if obj.object_type == "Group" and search_base:
                dlg = GroupPropertiesDialog(
                    self.ldap,
                    obj,
                    attrs,
                    search_base,
                    show_empty_attributes=self.show_empty_attributes,
                    on_toggle_show_empty_attributes=self.set_show_empty_attributes_preference,
                    parent=self,
                )
            elif obj.object_type == "User":
                dlg = UserPropertiesDialog(
                    self.ldap,
                    obj,
                    attrs,
                    search_base,
                    show_empty_attributes=self.show_empty_attributes,
                    on_toggle_show_empty_attributes=self.set_show_empty_attributes_preference,
                    parent=self,
                )
            elif obj.object_type == "Computer" and search_base:
                dlg = ComputerPropertiesDialog(
                    self.ldap,
                    obj,
                    attrs,
                    search_base,
                    show_empty_attributes=self.show_empty_attributes,
                    on_toggle_show_empty_attributes=self.set_show_empty_attributes_preference,
                    parent=self,
                )
            else:
                dlg = PropertiesDialog(self.ldap, obj, attrs, search_base or obj.dn, self)
        except Exception as e:
            self.show_error("Read failed", str(e))
            return
        finally:
            QApplication.restoreOverrideCursor()

        dlg.exec()

    def reset_password_for_object(self, obj: LdapObject) -> None:
        dlg = ResetPasswordDialog(obj.name, self)
        if dlg.exec() != QDialog.Accepted:
            return

        pw1, pw2 = dlg.passwords()
        if not pw1:
            self.show_error("Reset password failed", "Password cannot be blank.")
            return

        if pw1 != pw2:
            self.show_error("Reset password failed", "Passwords do not match.")
            return

        try:
            self.ldap.reset_password(obj.dn, pw1)
        except Exception as e:
            self.show_error("Reset password failed", str(e))
            return

        QMessageBox.information(self, "Password reset", f"Password reset for {obj.name}.")

    def copy_text_to_clipboard(self, text: str) -> None:
        QApplication.clipboard().setText(text)

    def export_table_list(self) -> None:
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "Export List", "There are no visible objects to export.")
            return

        default_name = "aduc-export.csv"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export List",
            default_name,
            "CSV files (*.csv);;Text files (*.txt)",
        )
        if not file_path:
            return

        ext = os.path.splitext(file_path)[1].lower()
        use_csv = "*.csv" in selected_filter or ext == ".csv"

        headers: list[str] = []
        for col in range(self.table.columnCount()):
            header_item = self.table.horizontalHeaderItem(col)
            headers.append(header_item.text() if header_item else f"Column {col + 1}")

        rows: list[list[str]] = []
        for row in range(self.table.rowCount()):
            row_values: list[str] = []
            for col in range(self.table.columnCount()):
                cell = self.table.item(row, col)
                row_values.append(cell.text() if cell else "")
            rows.append(row_values)

        try:
            if use_csv:
                if ext != ".csv":
                    file_path = f"{file_path}.csv"
                with open(file_path, "w", newline="", encoding="utf-8") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(headers)
                    writer.writerows(rows)
            else:
                if ext != ".txt":
                    file_path = f"{file_path}.txt"
                with open(file_path, "w", encoding="utf-8") as handle:
                    handle.write("\t".join(headers) + "\n")
                    for row_values in rows:
                        handle.write("\t".join(row_values) + "\n")
        except OSError as e:
            self.show_error("Export List failed", str(e))
            return

        QMessageBox.information(self, "Export List", f"Exported {len(rows)} entries to:\n{file_path}")

    def selected_table_objects(self) -> list[LdapObject]:
        selected_rows = sorted({idx.row() for idx in self.table.selectionModel().selectedRows()})
        selected_objects: list[LdapObject] = []
        for selected_row in selected_rows:
            selected_name_item = self.table.item(selected_row, 0)
            if not selected_name_item:
                continue
            selected_obj = selected_name_item.data(Qt.UserRole)
            if isinstance(selected_obj, LdapObject):
                selected_objects.append(selected_obj)
        return selected_objects

    def open_selected_properties(self) -> None:
        selected_objects = self.selected_table_objects()
        if len(selected_objects) == 1:
            self.open_properties(selected_objects[0])

    def find_in_current(self) -> None:
        if not self.current_dn:
            return
        dlg = SearchDialog(self.current_dn, self)
        if dlg.exec() == QDialog.Accepted:
            self.run_search(self.current_dn, dlg.term(), search_mode=dlg.search_mode())

    def rename_selected_object(self) -> None:
        selected_objects = self.selected_table_objects()
        if len(selected_objects) != 1:
            return

        obj = selected_objects[0]
        new_name, ok = QInputDialog.getText(self, "Rename", "New name:", text=obj.name)
        new_name = new_name.strip()
        if not ok or not new_name or new_name == obj.name:
            return

        try:
            self.ldap.rename_object(obj.dn, new_name)
        except Exception as e:
            self.show_error("Rename failed", str(e))
            return

        self.refresh_current()

    def delete_selected_objects(self) -> None:
        selected_objects = self.selected_table_objects()
        if not selected_objects:
            return

        names = "\n".join(f"- {obj.name}" for obj in selected_objects[:10])
        if len(selected_objects) > 10:
            names += f"\n- ... and {len(selected_objects) - 10} more"

        reply = QMessageBox.question(
            self,
            "Delete objects",
            f"Delete {len(selected_objects)} object(s)?\n\n{names}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        failures: list[str] = []
        for obj in selected_objects:
            try:
                self.ldap.delete_object(obj.dn)
            except Exception as e:
                failures.append(f"{obj.dn}: {e}")

        if failures:
            self.show_error("Delete failed", "\n".join(failures))
        self.refresh_current()

    @staticmethod
    def _display_name_from_dn(dn: str) -> str:
        first_rdn = dn.split(",", 1)[0].strip()
        if "=" in first_rdn:
            return first_rdn.split("=", 1)[1].strip() or dn
        return dn

    def confirm_move_objects(self, objects: list[LdapObject], target_dn: str) -> bool:
        if not objects:
            return False

        target_name = self._display_name_from_dn(target_dn)
        if len(objects) == 1:
            obj = objects[0]
            message = f"Are you sure you want to move {obj.name} to {target_name}?"
        else:
            message = f"Are you sure you want to move {len(objects)} objects to {target_name}?"

        reply = QMessageBox.question(
            self,
            "Confirm move",
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return reply == QMessageBox.Yes

    def _on_move_progress(self, index: int, total: int, object_name: str) -> None:
        if not self._move_progress_dialog:
            return
        self._move_progress_dialog.setLabelText(f"Moving {index}/{total}: {object_name}")
        self._move_progress_dialog.setValue(max(0, index - 1))

    def _on_move_finished(self, moved_count: int, failures: list[str]) -> None:
        if self._move_progress_dialog:
            self._move_progress_dialog.setValue(self._move_progress_dialog.maximum())
            self._move_progress_dialog.close()
            self._move_progress_dialog.deleteLater()
            self._move_progress_dialog = None

        QApplication.restoreOverrideCursor()

        if self._move_thread:
            self._move_thread.quit()

        self._move_worker = None

        if failures:
            self.show_error("Move failed", "\n".join(failures))

        if moved_count > 0:
            self.refresh_current()

    def _on_move_thread_finished(self) -> None:
        if self._move_thread:
            self._move_thread.deleteLater()
            self._move_thread = None
        self.statusBar().clearMessage()

    def move_objects_to_container(self, objects: list[LdapObject], target_dn: str) -> None:
        if not objects:
            return
        if self._move_thread is not None:
            self.statusBar().showMessage("A move operation is already in progress. Please wait.")
            return

        progress = QProgressDialog("Preparing move operation...", None, 0, len(objects), self)
        progress.setWindowTitle("Moving objects")
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowFlag(Qt.Dialog, True)
        progress.setCancelButton(None)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.setParent(self, Qt.Dialog)
        progress.ensurePolished()
        self.center_dialog_over_main_window(progress)
        progress.show()

        self._move_progress_dialog = progress
        self._move_thread = QThread(self)
        host = self.saved_host
        if not host and self.ldap.server:
            host = str(getattr(self.ldap.server, "host", "") or "")

        self._move_worker = MoveOperationWorker(
            self.auth_mode,
            host,
            self.saved_port,
            self.last_bind_user,
            self.last_bind_password,
            objects,
            target_dn,
        )
        self._move_worker.moveToThread(self._move_thread)

        self._move_thread.started.connect(self._move_worker.run)
        self._move_thread.finished.connect(self._on_move_thread_finished)
        self._move_worker.progress.connect(self._on_move_progress)
        self._move_worker.finished.connect(self._on_move_finished)

        QApplication.setOverrideCursor(Qt.WaitCursor)
        self.statusBar().showMessage("Move operation in progress...")
        QApplication.processEvents(QEventLoop.ExcludeUserInputEvents)
        self._move_thread.start()

    def move_selected_objects(self) -> None:
        selected_objects = self.selected_table_objects()
        if not selected_objects:
            return

        try:
            dlg = MoveObjectDialog(self.ldap, "Move", self)
            dlg.setWindowModality(Qt.WindowModal)
            dlg.ensurePolished()
            self.center_dialog_over_main_window(dlg)
            if dlg.exec() != QDialog.Accepted:
                return
        except Exception as e:
            self.show_error("Move", f"Unable to open Move dialog: {e}")
            return

        target_dn = dlg.selected_target_dn()
        if not target_dn:
            return

        if not self.confirm_move_objects(selected_objects, target_dn):
            return

        self.move_objects_to_container(selected_objects, target_dn)

    def add_selected_objects_to_group(self) -> None:
        selected_objects = self.selected_table_objects()
        if not selected_objects:
            return

        search_base = self.current_dn or (self.ldap.get_default_naming_context() or "")
        if not search_base:
            return

        dlg = SelectDirectoryObjectsDialog(self.ldap, search_base, self)
        if dlg.exec() != QDialog.Accepted:
            return

        selected_groups = [obj for obj in dlg.selected_objects() if obj.object_type == "Group"]
        if not selected_groups:
            QMessageBox.information(self, "Add to group", "Select at least one group.")
            return

        failures: list[str] = []
        added_count = 0
        for group_obj in selected_groups:
            for member_obj in selected_objects:
                if member_obj.dn == group_obj.dn:
                    continue
                try:
                    self.ldap.add_group_member(group_obj.dn, member_obj.dn)
                    added_count += 1
                except Exception as e:
                    if "entryAlreadyExists" in str(e):
                        continue
                    failures.append(f"{member_obj.name} -> {group_obj.name}: {e}")

        if failures:
            self.show_error("Add to group failed", "\n".join(failures))

        if added_count > 0:
            self.refresh_current()

    def on_directory_move_drop(self, target_dn: str, payload: list[dict[str, str]]) -> None:
        selected_dns = [str(entry.get("dn", "")).strip() for entry in payload]
        selected_dns = [dn for dn in selected_dns if dn]
        if not selected_dns:
            return

        objects: list[LdapObject] = []
        for dn in selected_dns:
            obj = self.ldap.get_object_summary(dn)
            if obj is not None:
                objects.append(obj)

        if not objects:
            self.statusBar().showMessage("Unable to resolve dragged directory objects.")
            return

        if not self.confirm_move_objects(objects, target_dn):
            return

        self.move_objects_to_container(objects, target_dn)

    def create_ou_in_current(self) -> None:
        if not self.current_dn:
            return

        name, ok = QInputDialog.getText(self, "New Organizational Unit", "Name:")
        name = name.strip()
        if not ok or not name:
            return

        try:
            self.ldap.create_organizational_unit(self.current_dn, name)
        except Exception as e:
            self.show_error("Create OU failed", str(e))
            return

        self.refresh_current()

    def create_user_under_dn(self, parent_dn: str) -> None:
        dlg = NewUserDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        name, sam_account_name, upn, description, password, enabled = dlg.values()
        if not name or not sam_account_name:
            self.show_error("Create user failed", "Name and logon name are required.")
            return

        try:
            self.ldap.create_user(
                parent_dn,
                name,
                sam_account_name,
                password=password,
                description=description,
                user_principal_name=upn,
                enabled=enabled,
            )
        except Exception as e:
            self.show_error("Create user failed", str(e))
            return

        self.refresh_current()

    def create_group_under_dn(self, parent_dn: str) -> None:
        dlg = NewGroupDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        name, sam_account_name, description, scope, security_enabled = dlg.values()
        if not name or not sam_account_name:
            self.show_error("Create group failed", "Name and pre-Windows 2000 name are required.")
            return

        try:
            self.ldap.create_group(
                parent_dn,
                name,
                sam_account_name,
                description=description,
                scope=scope,
                security_enabled=security_enabled,
            )
        except Exception as e:
            self.show_error("Create group failed", str(e))
            return

        self.refresh_current()

    def create_computer_under_dn(self, parent_dn: str) -> None:
        dlg = NewComputerDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        name, sam_account_name, description, enabled = dlg.values()
        if not name:
            self.show_error("Create computer failed", "Computer name is required.")
            return

        effective_sam = sam_account_name or name
        try:
            self.ldap.create_computer(
                parent_dn,
                name,
                effective_sam,
                description=description,
                enabled=enabled,
            )
        except Exception as e:
            self.show_error("Create computer failed", str(e))
            return

        self.refresh_current()

    def create_user_in_current(self) -> None:
        if not self.current_dn:
            return
        self.create_user_under_dn(self.current_dn)

    def create_group_in_current(self) -> None:
        if not self.current_dn:
            return
        self.create_group_under_dn(self.current_dn)

    def create_computer_in_current(self) -> None:
        if not self.current_dn:
            return
        self.create_computer_under_dn(self.current_dn)

    def allowed_creation_actions_for_dn(self, dn: str) -> set[str]:
        try:
            allowed_classes = self.ldap.get_allowed_child_classes(dn)
        except Exception:
            return set()

        allowed_actions: set[str] = set()
        for action_name, required_class in CREATABLE_CHILD_CLASS_BY_ACTION.items():
            if required_class not in allowed_classes:
                continue
            try:
                if self.ldap.can_create_child_class(dn, required_class):
                    allowed_actions.add(action_name)
            except Exception:
                continue
        return allowed_actions

    def add_creation_actions_to_menu(
        self,
        menu: QMenu,
        parent_dn: str,
        allowed_actions: Optional[set[str]] = None,
    ) -> dict[str, Optional[QAction]]:
        if allowed_actions is None:
            allowed_actions = self.allowed_creation_actions_for_dn(parent_dn)
        actions: dict[str, Optional[QAction]] = {
            "user": None,
            "group": None,
            "computer": None,
            "organizational_unit": None,
        }

        if "user" in allowed_actions:
            actions["user"] = menu.addAction("User")
        if "group" in allowed_actions:
            actions["group"] = menu.addAction("Group")
        if "computer" in allowed_actions:
            actions["computer"] = menu.addAction("Computer")
        if "organizational_unit" in allowed_actions:
            actions["organizational_unit"] = menu.addAction("Organizational Unit")

        return actions

    def add_new_submenu(self, menu: QMenu, parent_dn: str) -> tuple[Optional[QMenu], dict[str, Optional[QAction]]]:
        allowed_actions = self.allowed_creation_actions_for_dn(parent_dn)
        if not allowed_actions:
            return None, {
                "user": None,
                "group": None,
                "computer": None,
                "organizational_unit": None,
            }

        new_menu = menu.addMenu("New")
        create_actions = self.add_creation_actions_to_menu(new_menu, parent_dn, allowed_actions=allowed_actions)
        return new_menu, create_actions

    def ldap_object_from_tree_item(self, item: QTreeWidgetItem) -> Optional[LdapObject]:
        if not item:
            return None

        data = item.data(0, Qt.UserRole) or {}
        dn = data.get("dn")
        is_container = data.get("container", False)

        if not dn:
            return None

        object_classes: list[str] = ["container"] if is_container else []
        return LdapObject(
            dn=dn,
            name=item.text(0),
            object_classes=object_classes,
        )

    def on_tree_context_menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        if not item:
            return

        obj = self.ldap_object_from_tree_item(item)
        if not obj:
            return

        menu = QMenu(self)

        delegate_action = menu.addAction("Delegate Control")
        find_action = menu.addAction("Find...")
        menu.addSeparator()

        if obj.is_container:
            _, create_actions = self.add_new_submenu(menu, obj.dn)
        else:
            create_actions = {}
        create_user_action = create_actions.get("user")
        create_group_action = create_actions.get("group")
        create_computer_action = create_actions.get("computer")
        create_ou_action = create_actions.get("organizational_unit")

        all_tasks_menu = menu.addMenu("All Tasks")
        copy_dn_action = all_tasks_menu.addAction("Copy Distinguished Name")
        expand_action = all_tasks_menu.addAction("Expand") if obj.is_container else None

        menu.addSeparator()
        view_menu = menu.addMenu("View")
        details_action = view_menu.addAction("Details")
        details_action.setEnabled(False)

        menu.addSeparator()
        refresh_action = menu.addAction("Refresh")
        export_list_action = menu.addAction("Export List")

        menu.addSeparator()
        properties_action = menu.addAction("Properties")

        menu.addSeparator()
        help_action = menu.addAction("Help")

        chosen = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if not chosen:
            return

        if chosen == delegate_action:
            QMessageBox.information(self, "Delegate Control", "Delegate Control is not implemented yet.")
        elif chosen == find_action:
            dlg = SearchDialog(obj.dn, self)
            if dlg.exec() == QDialog.Accepted:
                self.run_search(obj.dn, dlg.term(), search_mode=dlg.search_mode())
        elif create_ou_action is not None and chosen == create_ou_action:
            name, ok = QInputDialog.getText(self, "New Organizational Unit", "Name:")
            name = name.strip()
            if ok and name:
                try:
                    self.ldap.create_organizational_unit(obj.dn, name)
                except Exception as e:
                    self.show_error("Create OU failed", str(e))
                    return
                self.refresh_current()
        elif create_user_action is not None and chosen == create_user_action:
            self.create_user_under_dn(obj.dn)
        elif create_group_action is not None and chosen == create_group_action:
            self.create_group_under_dn(obj.dn)
        elif create_computer_action is not None and chosen == create_computer_action:
            self.create_computer_under_dn(obj.dn)
        elif chosen == copy_dn_action:
            self.copy_text_to_clipboard(obj.dn)
        elif expand_action is not None and chosen == expand_action:
            self.load_tree_children(item)
            QTimer.singleShot(0, lambda i=item: self.tree.expandItem(i))
        elif chosen == refresh_action:
            if obj.is_container:
                data = item.data(0, Qt.UserRole) or {}
                data["loaded"] = False
                item.setData(0, Qt.UserRole, data)
                while item.childCount():
                    item.takeChild(0)
                self.load_tree_children(item)
                self.populate_main_pane(obj.dn, add_history=False)
        elif chosen == export_list_action:
            self.export_table_list()
        elif chosen == properties_action:
            self.open_properties(obj)
        elif chosen == help_action:
            QMessageBox.information(self, "Help", "Help topics are not implemented yet.")

    def on_table_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if not item:
            if not self.current_dn:
                return
            menu = QMenu(self)
            _, create_actions = self.add_new_submenu(menu, self.current_dn)
            create_user_action = create_actions.get("user")
            create_group_action = create_actions.get("group")
            create_computer_action = create_actions.get("computer")
            create_ou_action = create_actions.get("organizational_unit")
            menu.addSeparator()
            refresh_action = menu.addAction("Refresh")
            chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
            if not chosen:
                return
            if create_user_action is not None and chosen == create_user_action:
                self.create_user_under_dn(self.current_dn)
            elif create_group_action is not None and chosen == create_group_action:
                self.create_group_under_dn(self.current_dn)
            elif create_computer_action is not None and chosen == create_computer_action:
                self.create_computer_under_dn(self.current_dn)
            elif create_ou_action is not None and chosen == create_ou_action:
                name, ok = QInputDialog.getText(self, "New Organizational Unit", "Name:")
                name = name.strip()
                if ok and name:
                    try:
                        self.ldap.create_organizational_unit(self.current_dn, name)
                    except Exception as e:
                        self.show_error("Create OU failed", str(e))
                        return
                    self.refresh_current()
            elif chosen == refresh_action:
                self.refresh_current()
            return

        row = item.row()
        self.table.selectRow(row)

        selected_rows = sorted({idx.row() for idx in self.table.selectionModel().selectedRows()})
        selected_objects: list[LdapObject] = []
        for selected_row in selected_rows:
            selected_name_item = self.table.item(selected_row, 0)
            if not selected_name_item:
                continue
            selected_obj = selected_name_item.data(Qt.UserRole)
            if isinstance(selected_obj, LdapObject):
                selected_objects.append(selected_obj)

        if not selected_objects:
            return

        is_single = len(selected_objects) == 1
        obj = selected_objects[0]
        name_item = self.table.item(row, 0)
        if not name_item:
            return

        menu = QMenu(self)

        rename_action = None
        add_to_group_action = None
        if any(o.object_type in {"User", "Computer", "Group"} for o in selected_objects):
            add_to_group_action = menu.addAction("Add to group...")

        disable_action = None
        reset_password_action = None
        selected_users = [o for o in selected_objects if o.object_type == "User"]
        selected_computers = [o for o in selected_objects if o.object_type == "Computer"]
        disabled_users = [o for o in selected_users if o.user_disabled]
        enabled_users = [o for o in selected_users if not o.user_disabled]
        disabled_computers = [o for o in selected_computers if o.computer_disabled]
        enabled_computers = [o for o in selected_computers if not o.computer_disabled]

        if enabled_users or enabled_computers:
            disable_action = menu.addAction("Disable Account")

        if len(selected_users) == 1 and is_single:
            reset_password_action = menu.addAction("Reset Account")

        move_action = menu.addAction("Move...")
        manage_action = menu.addAction("Manage")

        menu.addSeparator()
        all_tasks_menu = menu.addMenu("All Tasks")
        all_tasks_menu.addAction("Find...").setEnabled(False)

        menu.addSeparator()
        cut_action = menu.addAction("Cut")
        delete_action = menu.addAction("Delete")
        if is_single and obj.object_type in {"User", "Group"}:
            rename_action = menu.addAction("Rename")

        menu.addSeparator()
        properties_action = menu.addAction("Properties")
        properties_action.setEnabled(is_single)
        properties_font = properties_action.font()
        properties_font.setBold(True)
        properties_action.setFont(properties_font)

        menu.addSeparator()
        help_action = menu.addAction("Help")

        copy_dn_action = None
        export_list_action = None

        open_action = None
        if is_single and obj.is_container:
            open_action = menu.addAction("Open")
            menu.addSeparator()
            _, create_actions = self.add_new_submenu(menu, obj.dn)
            new_user_action = create_actions.get("user")
            new_group_action = create_actions.get("group")
            new_computer_action = create_actions.get("computer")
            new_ou_action = create_actions.get("organizational_unit")
        else:
            new_user_action = None
            new_group_action = None
            new_computer_action = None
            new_ou_action = None

        enable_action = None
        unlock_action = None
        if selected_users:
            if disabled_users:
                enable_action = menu.addAction("Enable")
            unlock_action = menu.addAction("Unlock Account")
        elif selected_computers and disabled_computers:
            enable_action = menu.addAction("Enable")

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if not chosen:
            return

        if add_to_group_action is not None and chosen == add_to_group_action:
            self.add_selected_objects_to_group()
        elif disable_action is not None and chosen == disable_action:
            failed_dns: list[str] = []
            targets = selected_users if selected_users else selected_computers
            for target_obj in targets:
                try:
                    self.ldap.set_user_enabled(target_obj.dn, False)
                except Exception:
                    failed_dns.append(target_obj.dn)
            if failed_dns:
                self.show_error("Disable failed", "\n".join(failed_dns))
                return
            self.refresh_current()
        elif reset_password_action is not None and chosen == reset_password_action:
            self.reset_password_for_object(obj)
        elif chosen == move_action:
            self.move_selected_objects()
        elif chosen == manage_action:
            QMessageBox.information(self, "Manage", "Manage is not implemented yet.")
        elif chosen == cut_action:
            QMessageBox.information(self, "Cut", "Cut is not implemented yet.")
        elif chosen == delete_action:
            self.delete_selected_objects()
        elif rename_action is not None and chosen == rename_action:
            self.rename_selected_object()
        elif chosen == properties_action:
            self.open_properties(obj)
        elif chosen == help_action:
            QMessageBox.information(self, "Help", "Help topics are not implemented yet.")
        elif open_action is not None and chosen == open_action:
            self.populate_main_pane(obj.dn)
            tree_item = self.find_tree_item_by_dn(obj.dn)
            if tree_item:
                self.load_tree_children(tree_item)
                QTimer.singleShot(0, lambda i=tree_item: self.tree.expandItem(i))
                self.tree.setCurrentItem(tree_item)
        elif new_user_action is not None and chosen == new_user_action:
            self.create_user_under_dn(obj.dn)
        elif new_group_action is not None and chosen == new_group_action:
            self.create_group_under_dn(obj.dn)
        elif new_computer_action is not None and chosen == new_computer_action:
            self.create_computer_under_dn(obj.dn)
        elif new_ou_action is not None and chosen == new_ou_action:
            name, ok = QInputDialog.getText(self, "New Organizational Unit", "Name:")
            name = name.strip()
            if ok and name:
                try:
                    self.ldap.create_organizational_unit(obj.dn, name)
                except Exception as e:
                    self.show_error("Create OU failed", str(e))
                    return
                self.refresh_current()
        elif enable_action is not None and chosen == enable_action:
            failed_dns: list[str] = []
            targets = selected_users if selected_users else selected_computers
            for target_obj in targets:
                try:
                    self.ldap.set_user_enabled(target_obj.dn, True)
                except Exception:
                    failed_dns.append(target_obj.dn)
            if failed_dns:
                self.show_error("Enable failed", "\n".join(failed_dns))
                return
            self.refresh_current()
        elif unlock_action is not None and chosen == unlock_action:
            failed_dns: list[str] = []
            for user_obj in selected_users:
                try:
                    self.ldap.unlock_account(user_obj.dn)
                except Exception:
                    failed_dns.append(user_obj.dn)
            if failed_dns:
                self.show_error("Unlock account failed", "\n".join(failed_dns))
                return
            self.refresh_current()

    def on_group_membership_drop(self, group_obj: LdapObject, payload: list[dict[str, str]]) -> None:
        candidate_dns: list[str] = []
        for entry in payload:
            entry_type = str(entry.get("type", ""))
            if entry_type not in {"User", "Computer", "Group"}:
                continue
            dn = str(entry.get("dn", "")).strip()
            if not dn or dn == group_obj.dn:
                continue
            candidate_dns.append(dn)

        if not candidate_dns:
            QMessageBox.information(
                self,
                "No valid objects",
                "Drag users, computers, or groups onto a group to add membership.",
            )
            return

        unique_dns = list(dict.fromkeys(candidate_dns))
        added_count = 0
        skipped_count = 0
        failed: list[str] = []

        for member_dn in unique_dns:
            try:
                self.ldap.add_group_member(group_obj.dn, member_dn)
                added_count += 1
            except Exception as e:
                if "entryAlreadyExists" in str(e):
                    skipped_count += 1
                else:
                    failed.append(f"{member_dn}: {e}")

        if failed:
            self.show_error(
                "Add group members failed",
                "\n".join(failed),
            )

        QMessageBox.information(
            self,
            "Group membership updated",
            f"Group: {group_obj.name}\nAdded: {added_count}\nAlready members: {skipped_count}",
        )

        if self.current_dn:
            self.populate_main_pane(self.current_dn, add_history=False)

    def on_tree_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        data = item.data(0, Qt.UserRole) or {}
        dn = data.get("dn")
        if dn:
            with self.busy_cursor():
                self.populate_main_pane(dn)

    def on_tree_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        data = item.data(0, Qt.UserRole) or {}
        dn = data.get("dn")
        is_container = data.get("container", False)

        if not dn:
            return

        if is_container:
            with self.busy_cursor():
                self.tree.setCurrentItem(item)
                self.populate_main_pane(dn)
                self.load_tree_children(item)
                QTimer.singleShot(0, lambda i=item: self.tree.expandItem(i))
        else:
            obj = LdapObject(dn=dn, name=item.text(0), object_classes=[])
            self.open_properties(obj)

    def on_tree_expanded(self, item: QTreeWidgetItem) -> None:
        self.load_tree_children(item)

    def on_table_double_clicked(self, row: int, column: int) -> None:
        item = self.table.item(row, 0)
        if not item:
            return

        obj = item.data(Qt.UserRole)
        if not isinstance(obj, LdapObject):
            return

        if obj.is_container:
            self.populate_main_pane(obj.dn)
            current_tree_item = self.tree.currentItem()
            if current_tree_item:
                self.load_tree_children(current_tree_item)
                for i in range(current_tree_item.childCount()):
                    child_item = current_tree_item.child(i)
                    data = child_item.data(0, Qt.UserRole) or {}
                    if data.get("dn") == obj.dn:
                        current_tree_item.setExpanded(True)
                        child_item.setExpanded(True)
                        self.tree.setCurrentItem(child_item)
                        break
        else:
            self.open_properties(obj)

    def find_tree_item_by_dn(self, dn: str, loaded_only: bool = False) -> Optional[QTreeWidgetItem]:
        def walk(item: QTreeWidgetItem) -> Optional[QTreeWidgetItem]:
            data = item.data(0, Qt.UserRole) or {}
            if data.get("dn") == dn:
                return item

            if data.get("container", False) and not loaded_only:
                self.load_tree_children(item)

            for i in range(item.childCount()):
                found = walk(item.child(i))
                if found:
                    return found
            return None

        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            if not loaded_only:
                self.load_tree_children(top)
            found = walk(top)
            if found:
                return found
        return None

    def refresh_tree_item_children(self, item: QTreeWidgetItem) -> None:
        data = item.data(0, Qt.UserRole) or {}
        data["loaded"] = False
        item.setData(0, Qt.UserRole, data)
        while item.childCount():
            item.takeChild(0)
        self.load_tree_children(item)

    def refresh_current(self) -> None:
        if not self.current_dn:
            return
        self.populate_main_pane(self.current_dn, add_history=False)

        tree_item = None
        current_item = self.tree.currentItem()
        if current_item is not None:
            data = current_item.data(0, Qt.UserRole) or {}
            if data.get("dn") == self.current_dn:
                tree_item = current_item

        if tree_item is None:
            tree_item = self.find_tree_item_by_dn(self.current_dn, loaded_only=True)

        if tree_item:
            self.refresh_tree_item_children(tree_item)


def prompt_for_update_if_available() -> None:
    current_version = read_local_version()
    remote_version = fetch_remote_version()
    if not remote_version or not is_newer_version(current_version, remote_version):
        return

    box = QMessageBox()
    box.setIcon(QMessageBox.Information)
    box.setWindowTitle("Update available")
    box.setText(f"A newer version is available: {remote_version} (installed: {current_version}).")
    box.setInformativeText(
        "Would you like to open update instructions now?\n\n"
        f"Run this command in a terminal:\n{UPDATE_COMMAND}"
    )
    open_button = box.addButton("Open GitHub", QMessageBox.AcceptRole)
    box.addButton(QMessageBox.Close)
    box.exec()

    if box.clickedButton() is open_button:
        webbrowser.open("https://github.com/MakoWish/aduc_for_linux")


class StartupSplash(QSplashScreen):
    def __init__(self, duration_ms: int = 3000) -> None:
        splash_pixmap = QPixmap(SPLASH_IMAGE_FILE)
        self._image_loaded = not splash_pixmap.isNull()
        if self._image_loaded:
            splash_pixmap = splash_pixmap.scaled(
                SPLASH_IMAGE_SIZE,
                SPLASH_IMAGE_SIZE,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        else:
            splash_pixmap = QPixmap(480, 270)
            splash_pixmap.fill(QColor("black"))
        super().__init__(splash_pixmap)

        self._duration_ms = duration_ms
        self._start_time = 0.0
        self._fade_started = False
        self._content_opacity = 1.0

        self.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

        self.fade_animation = QPropertyAnimation(self, b"contentOpacity", self)
        self.fade_animation.setDuration(SPLASH_FADE_DURATION_MS)
        self.fade_animation.setStartValue(1.0)
        self.fade_animation.setEndValue(0.0)
        self.fade_animation.setEasingCurve(QEasingCurve.OutCubic)
        self.fade_animation.valueChanged.connect(lambda _: self.update())
        self.fade_animation.finished.connect(self.close)

    def get_content_opacity(self) -> float:
        return self._content_opacity

    def set_content_opacity(self, value: float) -> None:
        self._content_opacity = float(value)

    contentOpacity = Property(float, get_content_opacity, set_content_opacity)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
        painter.setOpacity(self._content_opacity)
        painter.drawPixmap(0, 0, self.pixmap())

        if not self._image_loaded:
            painter.setPen(QColor("white"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Starting ADUC for Linux...")

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._start_time == 0.0:
            self._start_time = time.monotonic()

    def _start_fade(self) -> None:
        if self._fade_started:
            return
        self._fade_started = True
        self.raise_()
        self._content_opacity = 1.0
        self.fade_animation.start()

    def finish_with_fade(self) -> None:
        elapsed_ms = 0
        if self._start_time:
            elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
        fade_delay_ms = max(0, self._duration_ms - self.fade_animation.duration() - elapsed_ms)
        QTimer.singleShot(fade_delay_ms, self._start_fade)


def launch_main_window(app: QApplication, splash: StartupSplash) -> None:
    main_window = MainWindow()
    main_window.show()
    splash.fade_animation.finished.connect(prompt_for_update_if_available)
    splash.finish_with_fade()
    app.main_window = main_window


def main() -> int:
    app = QApplication(sys.argv)
    app.setWindowIcon(build_application_icon())

    splash = StartupSplash()
    splash.show()

    QTimer.singleShot(0, lambda: launch_main_window(app, splash))
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
