#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import ssl
import sys
from dataclasses import dataclass
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QMenu,
    QDialog,
    QDialogButtonBox,
    QAbstractItemView,
    QFormLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QSplitter,
    QStyle,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ldap3 import ALL, BASE, LEVEL, SUBTREE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SASL, Connection, Server, Tls


# Hard-coded values used only during development
TEST_DC = ""
TEST_BIND_USER = ""
TEST_BIND_PASSWORD = ""

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "aduc-linux")
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")

CONTAINER_CLASSES = {
    "domain",
    "container",
    "organizationalUnit",
    "builtinDomain",
}

USER_CLASSES = {"user", "person", "organizationalPerson"}
GROUP_CLASSES = {"group"}
COMPUTER_CLASSES = {"computer"}


@dataclass
class LdapObject:
    dn: str
    name: str
    object_classes: list[str]
    description: str = ""

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
        if "organizationalUnit" in classes:
            return "Organizational Unit"
        if "container" in classes:
            return "Container"
        if "domain" in classes:
            return "Domain"
        return "Object"


class LdapManager:
    def __init__(self) -> None:
        self.server: Optional[Server] = None
        self.conn: Optional[Connection] = None

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

    def connect_kerberos(self, host: str, port: int = 636) -> None:
        tls = Tls(validate=ssl.CERT_REQUIRED)
        self.server = Server(host, port=port, use_ssl=True, get_info=ALL, tls=tls)
        self.conn = Connection(
            self.server,
            authentication=SASL,
            sasl_mechanism="GSSAPI",
            auto_bind=True,
            raise_exceptions=True,
        )

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

        if "namingContexts" in entry:
            try:
                for value in entry.namingContexts.values:
                    v = str(value)
                    if v and v not in contexts:
                        contexts.append(v)
            except Exception:
                pass

        return contexts

    def list_children(self, base_dn: str) -> list[LdapObject]:
        if not self.conn:
            return []

        self.conn.search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            search_scope=LEVEL,
            attributes=["distinguishedName", "name", "dNSHostName", "objectClass", "description"],
        )

        results: list[LdapObject] = []
        for entry in self.conn.entries:
            dn = str(entry.entry_dn)
            object_classes = [str(x) for x in entry.objectClass.values] if "objectClass" in entry else []
            if "computer" in object_classes and "dNSHostName" in entry:
                try:
                    dns_name = str(entry.dNSHostName)
                except Exception:
                    dns_name = ""
                name = dns_name or (str(entry.name) if "name" in entry else dn)
            else:
                name = str(entry.name) if "name" in entry else dn
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

    def search_objects(self, base_dn: str, term: str, size_limit: int = 200) -> list[LdapObject]:
        if not self.conn:
            return []

        safe_term = (
            term.replace("\\", r"\5c")
            .replace("*", r"\2a")
            .replace("(", r"\28")
            .replace(")", r"\29")
            .replace("\x00", "")
        )

        search_filter = (
            "(&"
            "(|"
            "(objectClass=user)"
            "(objectClass=group)"
            ")"
            "(|"
#            f"(cn=*{safe_term}*)"
            f"(name=*{safe_term}*)"
            f"(sAMAccountName=*{safe_term}*)"
            f"(displayName=*{safe_term}*)"
#            f"(description=*{safe_term}*)"
            ")"
            ")"
        )

        self.conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "name", "dNSHostName", "objectClass", "description"],
            size_limit=size_limit,
        )

        results: list[LdapObject] = []
        for entry in self.conn.entries:
            dn = str(entry.entry_dn)
            object_classes = [str(x) for x in entry.objectClass.values] if "objectClass" in entry else []
            if "computer" in object_classes and "dNSHostName" in entry:
                try:
                    dns_name = str(entry.dNSHostName)
                except Exception:
                    dns_name = ""
                name = dns_name or (str(entry.name) if "name" in entry else dn)
            else:
                name = str(entry.name) if "name" in entry else dn
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
        return results

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

    def get_object_summary(self, dn: str) -> Optional[LdapObject]:
        if not self.conn:
            return None

        self.conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["distinguishedName", "name", "dNSHostName", "objectClass", "description"],
        )
        if not self.conn.entries:
            return None

        entry = self.conn.entries[0]
        object_classes = [str(x) for x in entry.objectClass.values] if "objectClass" in entry else []
        if "computer" in object_classes and "dNSHostName" in entry:
            try:
                dns_name = str(entry.dNSHostName)
            except Exception:
                dns_name = ""
            name = dns_name or (str(entry.name) if "name" in entry else dn)
        else:
            name = str(entry.name) if "name" in entry else dn

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

    def replace_group_members(self, group_dn: str, member_dns: list[str]) -> None:
        if not self.conn:
            return

        ok = self.conn.modify(
            group_dn,
            {"member": [(MODIFY_REPLACE, member_dns)]},
        )
        if not ok:
            raise ValueError(str(self.conn.result))

    def search_directory_objects(self, base_dn: str, term: str, size_limit: int = 200) -> list[LdapObject]:
        if not self.conn:
            return []

        safe_term = (
            term.replace("\\", r"\5c")
            .replace("*", r"\2a")
            .replace("(", r"\28")
            .replace(")", r"\29")
            .replace("\x00", "")
        )

        search_filter = (
            "(&"
            "(|"
            "(objectClass=user)"
            "(objectClass=group)"
            "(objectClass=computer)"
            ")"
            "(|"
            f"(cn=*{safe_term}*)"
            f"(name=*{safe_term}*)"
            f"(sAMAccountName=*{safe_term}*)"
            f"(displayName=*{safe_term}*)"
            f"(description=*{safe_term}*)"
            ")"
            ")"
        )

        self.conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "name", "dNSHostName", "objectClass", "description"],
            size_limit=size_limit,
        )

        results: list[LdapObject] = []
        for entry in self.conn.entries:
            dn = str(entry.entry_dn)
            object_classes = [str(x) for x in entry.objectClass.values] if "objectClass" in entry else []
            if "computer" in object_classes and "dNSHostName" in entry:
                try:
                    dns_name = str(entry.dNSHostName)
                except Exception:
                    dns_name = ""
                name = dns_name or (str(entry.name) if "name" in entry else dn)
            else:
                name = str(entry.name) if "name" in entry else dn

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

        results.sort(key=lambda x: (x.object_type, x.name.lower()))
        return results


class ConnectDialog(QDialog):
    def __init__(self, auth_mode: str, saved_host: str = "", saved_port: int = 636, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Connect to Active Directory")
        self.auth_mode = auth_mode

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

        if self.auth_mode == "kerberos":
            self.bind_user_edit.setEnabled(False)
            self.password_edit.setEnabled(False)
            self.bind_user_edit.setPlaceholderText("Using current Kerberos ticket")
            self.password_edit.setPlaceholderText("Using current Kerberos ticket")

        form = QFormLayout()
        form.addRow("Server:", self.host_edit)
        form.addRow("Port:", self.port_edit)
        form.addRow("Bind user:", self.bind_user_edit)
        form.addRow("Password:", self.password_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, int, str, str]:
        return (
            self.host_edit.text().strip(),
            int(self.port_edit.text().strip()),
            self.bind_user_edit.text().strip(),
            self.password_edit.text(),
        )


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
        if self.selected_auth_mode() == "credentials":
            return False
        return bool(self.auto_connect_combo.currentData())

    def update_auto_connect_state(self) -> None:
        using_credentials = self.selected_auth_mode() == "credentials"
        if using_credentials:
            self.auto_connect_combo.setCurrentIndex(0)
        self.auto_connect_combo.setEnabled(not using_credentials)


class PropertiesDialog(QDialog):
    def __init__(self, obj: LdapObject, attrs: dict[str, list[str]], parent=None) -> None:
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

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)


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


class SelectDirectoryObjectsDialog(QDialog):
    def __init__(self, ldap: LdapManager, search_base: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Select Users, Contacts, Computers, or Groups")
        self.resize(800, 500)
        self.ldap = ldap
        self.search_base = search_base

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Name, sAMAccountName, displayName...")
        self.search_edit.returnPressed.connect(self.run_search)

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.run_search)

        search_row = QHBoxLayout()
        search_row.addWidget(self.search_edit)
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

    def run_search(self) -> None:
        term = self.search_edit.text().strip()
        if not term:
            return

        try:
            results = self.ldap.search_directory_objects(self.search_base, term)
        except Exception as e:
            QMessageBox.critical(self, "Search failed", str(e))
            return

        self.results.setRowCount(len(results))
        for row, obj in enumerate(results):
            name_item = QTableWidgetItem(obj.name)
            if obj.object_type == "User":
                icon = QIcon.fromTheme("user-identity")
                name_item.setIcon(icon if not icon.isNull() else self.style().standardIcon(QStyle.SP_FileIcon))
            elif obj.object_type == "Group":
                icon = QIcon.fromTheme("system-users")
                name_item.setIcon(icon if not icon.isNull() else self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
            elif obj.object_type == "Computer":
                icon = QIcon.fromTheme("computer")
                name_item.setIcon(icon if not icon.isNull() else self.style().standardIcon(QStyle.SP_ComputerIcon))
            name_item.setData(Qt.UserRole, obj)
            type_item = QTableWidgetItem(obj.object_type)
            dn_item = QTableWidgetItem(obj.dn)
            self.results.setItem(row, 0, name_item)
            self.results.setItem(row, 1, type_item)
            self.results.setItem(row, 2, dn_item)

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
    def __init__(self, ldap: LdapManager, group_obj: LdapObject, attrs: dict[str, list[str]], search_base: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(group_obj.name)
        self.resize(900, 600)
        self.ldap = ldap
        self.group_obj = group_obj
        self.attrs = attrs
        self.search_base = search_base
        self.original_member_dns: list[str] = []

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

        security_tab = QWidget()
        security_layout = QVBoxLayout(security_tab)
        security_layout.addWidget(QLabel("Security editor not implemented yet."))
        tabs.addTab(security_tab, "Security")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.on_ok)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

        self.add_btn.clicked.connect(self.add_members)
        self.remove_btn.clicked.connect(self.remove_selected_members)
        self.apply_btn.clicked.connect(self.apply_changes)

        self.load_members()
        self.load_member_of()

    def icon_for_object(self, obj: LdapObject) -> QIcon:
        style = self.style()
        if obj.object_type == "Organizational Unit":
            icon = QIcon.fromTheme("folder")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_DirIcon)
        if obj.object_type in {"Container", "Domain"}:
            icon = QIcon.fromTheme("folder")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_DirIcon)
        if obj.object_type == "User":
            icon = QIcon.fromTheme("user-identity")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_FileIcon)
        if obj.object_type == "Group":
            icon = QIcon.fromTheme("system-users")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_FileDialogDetailedView)
        if obj.object_type == "Computer":
            icon = QIcon.fromTheme("computer")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_ComputerIcon)
        icon = QIcon.fromTheme("text-x-generic")
        return icon if not icon.isNull() else style.standardIcon(QStyle.SP_FileIcon)

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

    def apply_changes(self) -> None:
        member_dns = self.current_member_dns()
        try:
            self.ldap.replace_group_members(self.group_obj.dn, member_dns)
        except Exception as e:
            QMessageBox.critical(self, "Apply failed", str(e))
            return
        self.original_member_dns = member_dns

    def on_ok(self) -> None:
        self.apply_changes()
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ADUC for Linux")
        self.resize(1400, 800)

        self.ldap = LdapManager()
        self.auth_mode = "credentials"
        self.saved_host = ""
        self.saved_port = 636
        self.auto_connect = False
        self.current_dn: Optional[str] = None
        self.load_settings()

        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Active Directory")
        self.tree.setExpandsOnDoubleClick(False)
        self.tree.itemClicked.connect(self.on_tree_clicked)
        self.tree.itemDoubleClicked.connect(self.on_tree_double_clicked)
        self.tree.itemExpanded.connect(self.on_tree_expanded)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_tree_context_menu)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Type", "Description", "Distinguished Name"])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.cellDoubleClicked.connect(self.on_table_double_clicked)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.on_table_context_menu)

        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.table)
        splitter.setStretchFactor(1, 1)

        central = QWidget()
        root_layout = QVBoxLayout(central)

        root_layout.addWidget(splitter, 1)

        self.setCentralWidget(central)

        file_menu = self.menuBar().addMenu("File")

        connect_action = QAction("Connect", self)
        connect_action.triggered.connect(self.show_connect_dialog)
        file_menu.addAction(connect_action)

        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_current)
        file_menu.addAction(refresh_action)

        options_action = QAction("Options", self)
        options_action.triggered.connect(self.show_options_dialog)
        file_menu.addAction(options_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        if self.auto_connect and self.saved_host:
            QTimer.singleShot(0, self.auto_connect_if_configured)

    def icon_for_object(self, obj: LdapObject) -> QIcon:
        style = self.style()
        if obj.object_type == "Organizational Unit":
            icon = QIcon.fromTheme("folder")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_DirIcon)
        if obj.object_type in {"Container", "Domain"}:
            icon = QIcon.fromTheme("folder")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_DirIcon)
        if obj.object_type == "User":
            icon = QIcon.fromTheme("user-identity")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_FileIcon)
        if obj.object_type == "Group":
            icon = QIcon.fromTheme("system-users")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_FileDialogDetailedView)
        if obj.object_type == "Computer":
            icon = QIcon.fromTheme("computer")
            return icon if not icon.isNull() else style.standardIcon(QStyle.SP_ComputerIcon)
        icon = QIcon.fromTheme("text-x-generic")
        return icon if not icon.isNull() else style.standardIcon(QStyle.SP_FileIcon)

    def show_error(self, title: str, message: str) -> None:
        QMessageBox.critical(self, title, message)

    def run_with_loading(self, message: str, action) -> None:
        loading = QProgressDialog(message, None, 0, 0, self)
        loading.setWindowTitle("Please wait")
        loading.setWindowModality(Qt.ApplicationModal)
        loading.setCancelButton(None)
        loading.setMinimumDuration(0)
        loading.show()
        QApplication.processEvents()

        try:
            action()
        finally:
            loading.close()

    def show_options_dialog(self) -> None:
        dlg = OptionsDialog(self.auth_mode, self)
        if dlg.exec() != QDialog.Accepted:
            return
        self.auth_mode = dlg.selected_auth_mode()

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

    def save_settings(self) -> None:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        data = {
            "auth_mode": self.auth_mode,
            "host": self.saved_host,
            "port": self.saved_port,
            "auto_connect": self.auto_connect,
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def auto_connect_if_configured(self) -> None:
        if self.auth_mode != "kerberos":
            return

        try:
            def connect_and_load() -> None:
                self.ldap.connect_kerberos(self.saved_host, port=self.saved_port)

                self.populate_roots()

            self.run_with_loading("Auto-connecting to Active Directory...", connect_and_load)
        except Exception as e:
            self.show_error("Auto-connect failed", str(e))
            return

    def show_options_dialog(self) -> None:
        dlg = OptionsDialog(self.auth_mode, self.auto_connect, self)
        if dlg.exec() != QDialog.Accepted:
            return

        self.auth_mode = dlg.selected_auth_mode()
        self.auto_connect = dlg.selected_auto_connect()
        self.save_settings()

    def show_connect_dialog(self) -> None:
        dlg = ConnectDialog(self.auth_mode, self.saved_host, self.saved_port, self)
        if dlg.exec() != QDialog.Accepted:
            return

        host, port, bind_user, password = dlg.values()

        try:
            if self.auth_mode == "kerberos":
                self.ldap.connect_kerberos(host, port=port)
            else:
                self.ldap.connect_simple(host, bind_user, password, port=port)
        except Exception as e:
            self.show_error("Connection failed", str(e))
            return

        self.saved_host = host
        self.saved_port = port
        self.save_settings()
        self.populate_roots()

    def populate_roots(self) -> None:
        self.tree.clear()
        self.table.setRowCount(0)
        self.current_dn = None

        try:
            contexts = self.ldap.get_naming_contexts()
        except Exception as e:
            self.show_error("Failed to read RootDSE", str(e))
            return

        for dn in contexts:
            item = QTreeWidgetItem([dn])
            item.setData(0, Qt.UserRole, {"dn": dn, "loaded": False, "container": True})
            item.setIcon(0, self.style().standardIcon(QStyle.SP_DirHomeIcon))
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            self.tree.addTopLevelItem(item)

    def load_tree_children(self, item: QTreeWidgetItem) -> None:
        data = item.data(0, Qt.UserRole) or {}
        if data.get("loaded"):
            return

        dn = data.get("dn")
        if not dn:
            return

        try:
            children = self.ldap.list_children(dn)
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
            children = self.ldap.list_children(dn)
        except Exception as e:
            self.show_error("List failed", str(e))
            return

        self.current_dn = dn

        self.table.setRowCount(len(children))

        for row, obj in enumerate(children):
            name_item = QTableWidgetItem(obj.name)
            name_item.setIcon(self.icon_for_object(obj))
            name_item.setData(Qt.UserRole, obj)

            type_item = QTableWidgetItem(obj.object_type)
            desc_item = QTableWidgetItem(obj.description)
            dn_item = QTableWidgetItem(obj.dn)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, type_item)
            self.table.setItem(row, 2, desc_item)
            self.table.setItem(row, 3, dn_item)

    def populate_search_results(self, results: list[LdapObject]) -> None:
        self.table.setRowCount(len(results))

        for row, obj in enumerate(results):
            name_item = QTableWidgetItem(obj.name)
            name_item.setIcon(self.icon_for_object(obj))
            name_item.setData(Qt.UserRole, obj)

            type_item = QTableWidgetItem(obj.object_type)
            desc_item = QTableWidgetItem(obj.description)
            dn_item = QTableWidgetItem(obj.dn)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, type_item)
            self.table.setItem(row, 2, desc_item)
            self.table.setItem(row, 3, dn_item)

    def run_search(self, base_dn: str, term: str) -> None:
        if not term:
            return

        try:
            results = self.ldap.search_objects(base_dn, term)
        except Exception as e:
            self.show_error("Search failed", str(e))
            return

        self.table.clearContents()
        self.populate_search_results(results)

    def open_properties(self, obj: LdapObject) -> None:
        try:
            attrs = self.ldap.get_object_attributes(obj.dn)
        except Exception as e:
            self.show_error("Read failed", str(e))
            return

        search_base = self.current_dn
        if not search_base:
            top = self.tree.topLevelItem(0)
            if top:
                data = top.data(0, Qt.UserRole) or {}
                search_base = data.get("dn")

        if obj.object_type == "Group" and search_base:
            dlg = GroupPropertiesDialog(self.ldap, obj, attrs, search_base, self)
        else:
            dlg = PropertiesDialog(obj, attrs, self)
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

        properties_action = menu.addAction("Properties")
        refresh_action = menu.addAction("Refresh")
        search_action = menu.addAction("Search...")
        copy_dn_action = menu.addAction("Copy Distinguished Name")

        expand_action = None
        if obj.is_container:
            expand_action = menu.addAction("Expand")

        chosen = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if not chosen:
            return

        if chosen == properties_action:
            self.open_properties(obj)
        elif chosen == refresh_action:
            if obj.is_container:
                data = item.data(0, Qt.UserRole) or {}
                data["loaded"] = False
                item.setData(0, Qt.UserRole, data)
                while item.childCount():
                    item.takeChild(0)
                self.load_tree_children(item)
                self.populate_main_pane(obj.dn, add_history=False)
        elif chosen == search_action:
            term, ok = QInputDialog.getText(self, "Search", f"Search under:\n{obj.dn}\n\nFind:")
            if ok:
                self.run_search(obj.dn, term.strip())
        elif chosen == copy_dn_action:
            self.copy_text_to_clipboard(obj.dn)
        elif expand_action is not None and chosen == expand_action:
            self.load_tree_children(item)
            QTimer.singleShot(0, lambda i=item: self.tree.expandItem(i))

    def on_table_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if not item:
            return

        row = item.row()
        name_item = self.table.item(row, 0)
        if not name_item:
            return

        obj = name_item.data(Qt.UserRole)
        if not isinstance(obj, LdapObject):
            return

        menu = QMenu(self)

        properties_action = menu.addAction("Properties")
        copy_dn_action = menu.addAction("Copy Distinguished Name")

        open_action = None
        if obj.is_container:
            open_action = menu.addAction("Open")

        enable_action = None
        disable_action = None
        unlock_action = None
        add_to_group_action = None
        remove_from_group_action = None
        reset_password_action = None
        if obj.object_type == "User":
            menu.addSeparator()
            reset_password_action = menu.addAction("Reset Password")
            enable_action = menu.addAction("Enable Account")
            disable_action = menu.addAction("Disable Account")
            unlock_action = menu.addAction("Unlock Account")

        if obj.object_type in {"User", "Computer"}:
            menu.addSeparator()
            add_to_group_action = menu.addAction("Add to Group...")
            remove_from_group_action = menu.addAction("Remove from Group...")

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if not chosen:
            return

        if chosen == properties_action:
            self.open_properties(obj)
        elif chosen == copy_dn_action:
            self.copy_text_to_clipboard(obj.dn)
        elif open_action is not None and chosen == open_action:
            self.populate_main_pane(obj.dn)
            tree_item = self.find_tree_item_by_dn(obj.dn)
            if tree_item:
                self.load_tree_children(tree_item)
                QTimer.singleShot(0, lambda i=tree_item: self.tree.expandItem(i))
                self.tree.setCurrentItem(tree_item)
        elif reset_password_action is not None and chosen == reset_password_action:
            self.reset_password_for_object(obj)
        elif enable_action is not None and chosen == enable_action:
            try:
                self.ldap.set_user_enabled(obj.dn, True)
            except Exception as e:
                self.show_error("Enable account failed", str(e))
                return
            self.refresh_current()
        elif disable_action is not None and chosen == disable_action:
            try:
                self.ldap.set_user_enabled(obj.dn, False)
            except Exception as e:
                self.show_error("Disable account failed", str(e))
                return
            self.refresh_current()
        elif unlock_action is not None and chosen == unlock_action:
            try:
                self.ldap.unlock_account(obj.dn)
            except Exception as e:
                self.show_error("Unlock account failed", str(e))
                return
            self.refresh_current()
        elif add_to_group_action is not None and chosen == add_to_group_action:
            pass
        elif remove_from_group_action is not None and chosen == remove_from_group_action:
            pass

    def on_tree_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        data = item.data(0, Qt.UserRole) or {}
        dn = data.get("dn")
        if dn:
            self.populate_main_pane(dn)

    def on_tree_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        data = item.data(0, Qt.UserRole) or {}
        dn = data.get("dn")
        is_container = data.get("container", False)

        if not dn:
            return

        if is_container:
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

    def find_tree_item_by_dn(self, dn: str) -> Optional[QTreeWidgetItem]:
        def walk(item: QTreeWidgetItem) -> Optional[QTreeWidgetItem]:
            data = item.data(0, Qt.UserRole) or {}
            if data.get("dn") == dn:
                return item

            if data.get("container", False):
                self.load_tree_children(item)

            for i in range(item.childCount()):
                found = walk(item.child(i))
                if found:
                    return found
            return None

        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            self.load_tree_children(top)
            found = walk(top)
            if found:
                return found
        return None

    def refresh_current(self) -> None:
        if not self.current_dn:
            return
        self.populate_main_pane(self.current_dn, add_history=False)

        tree_item = self.find_tree_item_by_dn(self.current_dn)
        if tree_item:
            data = tree_item.data(0, Qt.UserRole) or {}
            data["loaded"] = False
            tree_item.setData(0, Qt.UserRole, data)
            while tree_item.childCount():
                tree_item.takeChild(0)
            self.load_tree_children(tree_item)


def main() -> int:
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
