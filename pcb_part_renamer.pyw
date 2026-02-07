#!/usr/bin/env pythonw
"""PCB Part Renamer

Minimal GUI tool to inspect and rename part labels inside encrypted XZZ PCB files

@author: nitefood
@homepage: https://github.com/nitefood/pcb-part-renamer
@license: MIT
"""
from __future__ import annotations

import json
import os
import sys
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Global version
VERSION = "1.0"

try:
    from PySide6 import QtWidgets, QtCore, QtGui
except Exception:
    try:
        from PyQt5 import QtWidgets, QtCore, QtGui
    except Exception:
        raise SystemExit("Install PySide6 or PyQt5: pip install PySide6")

try:
    import binascii
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import pad, unpad
except Exception:
    raise SystemExit("Install pycryptodome: pip install pycryptodome")

# --- PCB format encryption / decryption code ---

MASTER_KEY = "DCFC12AC00000000"

SEARCH_PATTERN = bytes([
    0x76,
    0x36,
    0x76,
    0x36,
    0x35,
    0x35,
    0x35,
    0x76,
    0x36,
    0x76,
    0x36,
    0x3D,
    0x3D,
    0x3D,
    0xD7,
    0xE8,
    0xD6,
    0xB5,
    0x0A,
])


def hex_to_bytes(hex_string: str) -> bytes:
    return binascii.unhexlify(hex_string)


def decrypt_des_block(data: bytes) -> bytes:
    key = hex_to_bytes(MASTER_KEY)
    des = DES.new(key, DES.MODE_ECB)
    dec = des.decrypt(data)
    try:
        return unpad(dec, DES.block_size)
    except ValueError:
        return dec


def encrypt_des_block(plaintext: bytes, target_size: Optional[int] = None) -> bytes:
    key = hex_to_bytes(MASTER_KEY)
    des = DES.new(key, DES.MODE_ECB)
    if target_size is not None:
        if len(plaintext) % DES.block_size == 0 and target_size == len(plaintext):
            return des.encrypt(plaintext)
        padded = pad(plaintext, DES.block_size)
        if len(padded) == target_size:
            return des.encrypt(padded)
        return des.encrypt(padded)
    padded = pad(plaintext, DES.block_size)
    return des.encrypt(padded)


def find_xor_region(data: bytes) -> Tuple[int, int]:
    key = data[0x10]
    if key == 0x00:
        return (0x00, 0)
    pos = data.find(SEARCH_PATTERN)
    if pos == -1:
        return (key, len(data))
    return (key, pos)


def find_xor_length_only(data: bytes) -> int:
    pos = data.find(SEARCH_PATTERN)
    if pos == -1:
        return len(data)
    return pos


def apply_xor_region(arr: bytearray, key: int, length: int) -> None:
    for i in range(length):
        arr[i] = arr[i] ^ key


def parse_blocks(data: bytearray) -> List[dict]:
    blocks = []
    cur = 0x40
    if cur + 4 > len(data):
        return blocks
    main_data_blocks_size = struct.unpack("<I", data[cur : cur + 4])[0]
    cur += 4
    end = 0x44 + main_data_blocks_size
    while cur < end and cur + 5 <= len(data):
        block_type_offset = cur
        block_type = data[cur : cur + 1]
        cur += 1
        block_size_offset = cur
        block_size = struct.unpack("<I", data[cur : cur + 4])[0]
        cur += 4
        block_data_offset = cur
        if cur + block_size > len(data):
            break
        block_data = bytes(data[cur : cur + block_size])

        entry = {
            "block_type_offset": block_type_offset,
            "block_size_offset": block_size_offset,
            "block_data_offset": block_data_offset,
            "block_size": block_size,
            "block_type": block_type,
            "block_data_encrypted": block_data,
            "decrypted": None,
            "label": None,
            "label_len_offset_in_decrypted": None,
            "label_offset_in_decrypted": None,
        }

        if block_type == b"\x07":
            try:
                dec = decrypt_des_block(block_data)
                entry["decrypted"] = dec
                p = 22
                if p + 4 <= len(dec):
                    adv = struct.unpack("<I", dec[p : p + 4])[0]
                    p += adv
                    p += 4
                    p += 31
                    if p + 4 <= len(dec):
                        label_len = struct.unpack("<I", dec[p : p + 4])[0]
                        p += 4
                        if p + label_len <= len(dec):
                            raw_label = dec[p : p + label_len]
                            try:
                                label = raw_label.decode("utf-8")
                            except Exception:
                                try:
                                    label = raw_label.decode("gb2312")
                                except Exception:
                                    label = raw_label.decode("latin-1")
                            entry["label"] = label
                            entry["label_len_offset_in_decrypted"] = p - 4
                            entry["label_offset_in_decrypted"] = p
            except Exception:
                pass

        blocks.append(entry)
        cur += block_size

    return blocks


# --- GUI code ---


class PartItem(QtWidgets.QTreeWidgetItem):
    def __init__(self, label: str, capacity: int):
        super().__init__([label, ""])
        self.orig = label
        self.capacity = capacity


class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"PCB Part Renamer v{VERSION}")
        self.resize(800, 500)

        # main horizontal layout: left = controls + list, right = changed parts panel
        main_layout = QtWidgets.QHBoxLayout(self)

        # left column (existing controls)
        left_col = QtWidgets.QVBoxLayout()
        hl = QtWidgets.QHBoxLayout()
        self.open_btn = QtWidgets.QPushButton("Open source .pcb")
        self.load_map_btn = QtWidgets.QPushButton("Load .partnames file")
        hl.addWidget(self.open_btn)
        hl.addWidget(self.load_map_btn)
        # disabled until a .pcb file is loaded
        self.load_map_btn.setEnabled(False)
        left_col.addLayout(hl)

        # Search box with fuzzy autocomplete
        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Search parts")
        # disabled until a .pcb file is loaded
        self.search_box.setEnabled(False)
        left_col.addWidget(self.search_box)
        self.completer_model = QtCore.QStringListModel()
        self.completer = QtWidgets.QCompleter(self.completer_model, self)
        self.completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
        try:
            self.completer.setFilterMode(QtCore.Qt.MatchContains)
        except Exception:
            pass
        self.completer.setCompletionMode(QtWidgets.QCompleter.PopupCompletion)
        self.search_box.setCompleter(self.completer)
        self.search_box.textChanged.connect(self.on_search_text_changed)
        self.completer.activated.connect(self.on_completer_activated)

        self.list = QtWidgets.QTreeWidget()
        self.list.setColumnCount(2)
        self.list.setHeaderLabels(["Current", "New"])
        self.list.setRootIsDecorated(False)
        self.list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        # itemDoubleClicked for QTreeWidget provides (item, column)
        self.list.itemDoubleClicked.connect(lambda it, col: self.edit_item(it))
        # show hint in the New column when an item is selected
        self.edit_hint_text = "Double-click to edit"
        self.list.itemSelectionChanged.connect(self.on_list_selection_changed)
        left_col.addWidget(self.list)

        btns = QtWidgets.QHBoxLayout()
        self.apply_btn = QtWidgets.QPushButton("Save modified .pcb")
        btns.addStretch()
        btns.addWidget(self.apply_btn)
        # disabled until a .pcb file is loaded
        self.apply_btn.setEnabled(False)
        left_col.addLayout(btns)

        main_layout.addLayout(left_col, 3)

        # right column: changed parts panel
        right_col = QtWidgets.QVBoxLayout()
        self.changed_label = QtWidgets.QLabel("Changed Parts")
        self.changed_label.setAlignment(QtCore.Qt.AlignCenter)
        right_col.addWidget(self.changed_label)
        self.changed_list = QtWidgets.QListWidget()
        self.changed_list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        right_col.addWidget(self.changed_list)
        self.clear_changed_btn = QtWidgets.QPushButton("Clear Changes")
        right_col.addWidget(self.clear_changed_btn)
        # disabled until a .pcb file is loaded
        self.clear_changed_btn.setEnabled(False)
        # About button shows project info and homepage link
        self.about_btn = QtWidgets.QPushButton("About")
        right_col.addWidget(self.about_btn)
        main_layout.addLayout(right_col, 1)

        self.open_btn.clicked.connect(self.open_pcb)
        self.load_map_btn.clicked.connect(self.load_mappings)
        self.apply_btn.clicked.connect(self.apply_and_save)
        self.clear_changed_btn.clicked.connect(self.clear_changed_list)
        self.changed_list.itemClicked.connect(self.on_changed_item_clicked)
        self.about_btn.clicked.connect(self.show_about_dialog)

        self.loaded_file = None
        self.orig_arr = None
        self.data = None
        self.blocks = []
        self.mappings: List[Dict] = []
        # track whether there are unsaved changes (mappings modified)
        self.is_dirty = False
        # ensure window title reflects dirty state
        self.update_window_title()

    # --- Search / completer helpers ---
    def build_completer_list(self) -> List[str]:
        return [b.get("label") for b in self.blocks if b.get("label")]

    def refresh_completer(self) -> None:
        self.completer_model.setStringList(self.build_completer_list())

    def fuzzy_match(self, pattern: str, text: str) -> bool:
        # simple subsequence fuzzy match (characters in order)
        if not pattern:
            return True
        it = iter(text)
        return all(c in it for c in pattern)

    def on_search_text_changed(self, text: str) -> None:
        pat = text.lower()
        # when searching, filter visible items in the tree to matching rows
        matches: List[str] = []
        for i in range(self.list.topLevelItemCount()):
            it = self.list.topLevelItem(i)
            lab = getattr(it, "orig", None)
            if not lab:
                it.setHidden(True)
                continue
            if not pat or self.fuzzy_match(pat, lab.lower()):
                it.setHidden(False)
                matches.append(lab)
            else:
                it.setHidden(True)

        # update completer suggestions to currently visible matches
        if not pat:
            self.refresh_completer()
        else:
            self.completer_model.setStringList(matches)

        if matches:
            self.select_item_by_label(matches[0])
        else:
            self.list.clearSelection()

    def on_completer_activated(self, text: str) -> None:
        self.select_item_by_label(text)
        self.search_box.clearFocus()

    def select_item_by_label(self, label: str) -> None:
        for i in range(self.list.topLevelItemCount()):
            it = self.list.topLevelItem(i)
            if getattr(it, "orig", None) == label:
                self.list.setCurrentItem(it)
                self.list.scrollToItem(it, QtWidgets.QAbstractItemView.PositionAtCenter)
                return

    def update_item_renamed_state(self, item: PartItem, label: str) -> None:
        for m in self.mappings:
            if m.get("old") == label:
                brush = QtGui.QBrush(QtGui.QColor("#d0f0d0"))
                item.setBackground(0, brush)
                item.setBackground(1, brush)
                item.setToolTip(0, f"Renamed → {m.get('new')}")
                item.setToolTip(1, f"Renamed → {m.get('new')}")
                item.setText(1, m.get("new") or "")
                return
        brush = QtGui.QBrush(QtGui.QColor("#ffffff"))
        item.setBackground(0, brush)
        item.setBackground(1, brush)
        item.setToolTip(0, "")
        item.setToolTip(1, "")
        # ensure new column cleared when not renamed
        if item.text(1):
            item.setText(1, "")


    # --- Changed parts panel helpers ---
    def refresh_changed_list(self) -> None:
        self.changed_list.clear()
        for m in self.mappings:
            text = f"{m.get('old')} → {m.get('new')}"
            it = QtWidgets.QListWidgetItem(text)
            it.setData(QtCore.Qt.UserRole, m.get('old'))
            # match the green used in the main list for renamed items
            brush = QtGui.QBrush(QtGui.QColor("#d0f0d0"))
            it.setBackground(brush)
            it.setToolTip(f"Renamed → {m.get('new')}")
            self.changed_list.addItem(it)

    def update_window_title(self) -> None:
        """Update the main window title to include version and dirty asterisk."""
        title = f"PCB Part Renamer v{VERSION}"
        # include current filename if loaded
        try:
            if getattr(self, "loaded_file", None):
                title += " - " + os.path.basename(self.loaded_file)
        except Exception:
            pass
        if getattr(self, "is_dirty", False):
            title += " *"
        try:
            self.setWindowTitle(title)
        except Exception:
            pass

    def clear_changed_list(self) -> None:
        self.mappings = []
        self.is_dirty = False
        self.update_window_title()
        # clear new column and visual state
        for i in range(self.list.topLevelItemCount()):
            it = self.list.topLevelItem(i)
            it.setText(1, "")
            self.update_item_renamed_state(it, getattr(it, 'orig', None))
        self.refresh_changed_list()

    def on_changed_item_clicked(self, item: QtWidgets.QListWidgetItem) -> None:
        orig = item.data(QtCore.Qt.UserRole)
        if orig:
            self.select_item_by_label(orig)

    def show_about_dialog(self) -> None:
        """Show an About dialog with the version and project homepage."""
        text = (
            f"<b>PCB Part Renamer v{VERSION}</b><br><br>"
            "Minimal GUI tool to inspect and rename part labels inside encrypted XZZ PCB files.<br><br>"
            "Bug reports/Pull requests/Discussions: "
            "<a href=\"https://github.com/nitefood/pcb-part-renamer\">https://github.com/nitefood/pcb-part-renamer</a>"
        )
        msg = QtWidgets.QMessageBox(self)
        msg.setWindowTitle("About")
        msg.setTextFormat(QtCore.Qt.RichText)
        msg.setText(text)
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
        # allow clicking the link to open in the default browser
        msg.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        msg.exec_()

    def open_pcb(self):
        # if there are unsaved changes, confirm first
        res = self.confirm_save_if_dirty()
        if res == "cancel":
            return
        if res == "discard":
            # user chose to discard unsaved edits — clear mappings/state
            self.clear_changed_list()

        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open PCB file", "", "PCB Files (*.pcb);;All Files (*)")
        if not path:
            return
        self.load_pcb(path)

    def load_pcb(self, path: str):
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        with open(path, "rb") as fh:
            orig = fh.read()
        self.loaded_file = path
        self.orig_arr = bytearray(orig)
        key_byte, xor_len = find_xor_region(self.orig_arr)
        if key_byte != 0:
            data = bytearray(self.orig_arr)
            apply_xor_region(data, key_byte, xor_len)
        else:
            data = bytearray(self.orig_arr)
        self.data = data
        self.blocks = parse_blocks(data)
        self.populate_list()
        self.refresh_completer()
        self.refresh_changed_list()

        # enable actions now that a file is loaded
        try:
            self.apply_btn.setEnabled(True)
            self.clear_changed_btn.setEnabled(True)
            self.search_box.setEnabled(True)
            self.load_map_btn.setEnabled(True)
        except Exception:
            pass
        # update title to show loaded filename
        self.update_window_title()

        # If a sibling .partnames file exists, prompt to load it
        map_path = os.path.splitext(self.loaded_file)[0] + ".partnames"
        try:
            if os.path.exists(map_path):
                resp = QtWidgets.QMessageBox.question(
                    self,
                    "Load mappings",
                    f"Found mapping file {map_path}. Load mappings?",
                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                )
                if resp == QtWidgets.QMessageBox.Yes:
                    with open(map_path, "r", encoding="utf-8") as fh:
                        arr = json.load(fh)
                    self.apply_mappings(arr)
        except Exception:
            # ignore any errors reading the optional mappings file
            pass

    def populate_list(self):
        self.list.clear()
        for b in self.blocks:
            label = b.get("label")
            if label:
                dec = b.get("decrypted")
                if dec and b.get("label_len_offset_in_decrypted") is not None:
                    off = b["label_len_offset_in_decrypted"]
                    try:
                        cap = int.from_bytes(dec[off:off+4], "little")
                    except Exception:
                        cap = dec[off]
                else:
                    cap = len(label)
                item = PartItem(label, cap)
                self.list.addTopLevelItem(item)
                self.update_item_renamed_state(item, label)

    def edit_item(self, item: PartItem):
        new, ok = QtWidgets.QInputDialog.getText(self, "Edit partname", f"New name for {item.orig} (max {item.capacity}):")
        if not ok:
            return
        new = new.strip()
        if len(new.encode("utf-8")) > item.capacity:
            QtWidgets.QMessageBox.warning(self, "Too long", f"Name exceeds max byte capacity ({item.capacity}).")
            return
        # store new name in second column
        item.setText(1, new)
        mapping = {"old": item.orig, "new": new, "encoding": "utf-8", "max_len": item.capacity, "timestamp": datetime.utcnow().isoformat() + "Z"}
        for i, m in enumerate(self.mappings):
            if m.get("old") == item.orig:
                self.mappings[i] = mapping
                break
        else:
            self.mappings.append(mapping)
        # mark unsaved changes
        self.is_dirty = True
        self.update_window_title()
        self.update_item_renamed_state(item, item.orig)
        # keep completer list showing original labels; no change needed
        self.refresh_changed_list()

    def load_mappings(self):
        # if there are unsaved changes, confirm first
        res = self.confirm_save_if_dirty()
        if res == "cancel":
            return
        if res == "discard":
            # discard any unsaved mappings before loading a new mapping file
            self.clear_changed_list()

        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load partnames mapping", "", "Partnames Files (*.partnames);;All Files (*)")
        if not path:
            return
        with open(path, "r", encoding="utf-8") as fh:
            arr = json.load(fh)
        self.apply_mappings(arr)
        # ensure title updated (apply_mappings clears dirty)
        self.update_window_title()
        # loaded from file -> not dirty
        self.is_dirty = False

    def apply_mappings(self, arr: List[Dict]) -> None:
        """Apply mappings from an array of mapping dicts to the UI state."""
        self.mappings = arr
        for i in range(self.list.topLevelItemCount()):
            it = self.list.topLevelItem(i)
            for m in arr:
                if getattr(it, "orig", None) == m.get("old"):
                    it.setText(1, m.get("new") or "")
                    self.update_item_renamed_state(it, it.orig)
                    break
        self.refresh_completer()
        self.refresh_changed_list()
        # applying mappings from a source isn't considered an unsaved modification
        self.is_dirty = False
        self.update_window_title()

    def on_list_selection_changed(self) -> None:
        """Update the 'New' column to show an edit hint for the selected item.

        Restores other items to their normal renamed/not-renamed state.
        """
        # reset all items to their canonical state
        for i in range(self.list.topLevelItemCount()):
            it = self.list.topLevelItem(i)
            # restore renamed state or clear new column
            self.update_item_renamed_state(it, getattr(it, 'orig', None))
            # reset font/foreground for new column
            it.setFont(1, QtGui.QFont())
            it.setForeground(1, QtGui.QBrush(QtGui.QColor("#000000")))

        cur = self.list.currentItem()
        if not cur:
            return
        # only show the hint when the item isn't already renamed (new column empty)
        if not cur.text(1):
            cur.setText(1, self.edit_hint_text)
            cur.setForeground(1, QtGui.QBrush(QtGui.QColor("#808080")))
            f = QtGui.QFont()
            f.setItalic(True)
            cur.setFont(1, f)

    def closeEvent(self, event) -> None:
        """Prompt to save if there are unsaved changes before quitting."""
        if not getattr(self, "is_dirty", False):
            event.accept()
            return

        msg = QtWidgets.QMessageBox(self)
        msg.setWindowTitle("Unsaved changes")
        msg.setText("There are unsaved changes. Save before quitting?")
        msg.setIcon(QtWidgets.QMessageBox.Warning)
        msg.setStandardButtons(QtWidgets.QMessageBox.Save | QtWidgets.QMessageBox.Discard | QtWidgets.QMessageBox.Cancel)
        resp = msg.exec_()
        if resp == QtWidgets.QMessageBox.Save:
            saved = self.apply_and_save()
            if saved:
                event.accept()
            else:
                # user cancelled or save failed
                event.ignore()
        elif resp == QtWidgets.QMessageBox.Discard:
            event.accept()
        else:
            event.ignore()

    def confirm_save_if_dirty(self) -> bool:
        """If there are unsaved changes, prompt the user to Save/Discard/Cancel.

        Returns one of: 'none' (no dirty), 'saved', 'discard', 'cancel'.
        """
        if not getattr(self, "is_dirty", False):
            return "none"

        msg = QtWidgets.QMessageBox(self)
        msg.setWindowTitle("Unsaved changes")
        msg.setText("There are unsaved changes. Save before continuing?")
        msg.setIcon(QtWidgets.QMessageBox.Warning)
        msg.setStandardButtons(QtWidgets.QMessageBox.Save | QtWidgets.QMessageBox.Discard | QtWidgets.QMessageBox.Cancel)
        resp = msg.exec_()
        if resp == QtWidgets.QMessageBox.Save:
            saved = bool(self.apply_and_save())
            return "saved" if saved else "cancel"
        if resp == QtWidgets.QMessageBox.Discard:
            return "discard"
        return "cancel"

    def apply_and_save(self):
        if not self.loaded_file:
            QtWidgets.QMessageBox.information(self, "No file", "Open a .pcb file first")
            return False
        map_by_old = {m["old"]: m for m in self.mappings}
        changed = 0
        for b in self.blocks:
            lab = b.get("label")
            if not lab:
                continue
            if lab in map_by_old:
                m = map_by_old[lab]
                new_name = m.get("new")
                enc = m.get("encoding", "utf-8")
                dec = bytearray(b["decrypted"])
                l_off = b["label_len_offset_in_decrypted"]
                lab_off = b["label_offset_in_decrypted"]
                try:
                    old_len = struct.unpack("<I", dec[l_off:l_off+4])[0]
                except Exception:
                    old_len = dec[l_off]
                new_bytes = new_name.encode(enc)
                if len(new_bytes) > old_len:
                    continue
                dec[l_off:l_off+4] = struct.pack("<I", len(new_bytes))
                dec[lab_off:lab_off+old_len] = new_bytes + b"\x00" * (old_len - len(new_bytes))
                new_enc = encrypt_des_block(bytes(dec), b["block_size"])
                off = b["block_data_offset"]
                self.data[off:off+b["block_size"]] = new_enc[:b["block_size"]]
                changed += 1

        if changed == 0:
            QtWidgets.QMessageBox.information(self, "No changes", "No mappings applied or no matching labels found.")
            return False

        out = bytearray(self.data)
        key_byte, xor_len = find_xor_region(self.orig_arr)
        if key_byte != 0:
            new_xor_len = find_xor_length_only(self.data)
            apply_xor_region(out, key_byte, new_xor_len)

        # Ask user where to save the modified PCB (allow changing filename/path)
        # suggest the original filename so the user can choose to overwrite or rename
        suggested = self.loaded_file
        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save modified PCB", suggested, "PCB Files (*.pcb);;All Files (*)")
        if not save_path:
            return
        with open(save_path, "wb") as fh:
            fh.write(out)

        # Save mappings using the original loaded filename (keep mapping tied to original)
        map_path = os.path.splitext(self.loaded_file)[0] + ".partnames"
        with open(map_path, "w", encoding="utf-8") as fh:
            json.dump(self.mappings, fh, ensure_ascii=False, indent=2)

        QtWidgets.QMessageBox.information(self, "Saved", f"Wrote {save_path} and mappings to {map_path}")
        # keep changed list in sync after saving
        self.refresh_changed_list()
        # mark as saved
        self.is_dirty = False
        self.update_window_title()
        return True


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    # ensure we intercept close to warn about unsaved changes
    def on_about_to_quit():
        # pass; actual prompt handled in MainWindow.closeEvent
        return
    app.aboutToQuit.connect(on_about_to_quit)
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
