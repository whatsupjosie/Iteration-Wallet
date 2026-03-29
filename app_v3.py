"""
Iteration Wallet — Application Entry Point
==========================================
"Let find something right where YOU left it."

© 2025 Rear View Foresight LLC — Josie Curtsey Cobbley
Feic Mo Chroí — See My Heart.

This module owns:
  - VaultAPI: the JS-callable bridge between the HTML interface and VaultEngine
  - start(): creates the pywebview window and launches the app

All vault logic lives in vault_engine_v2.py.
This file only translates between the web layer and the engine.
"""

import os
import json
import webview
import logging
from pathlib import Path
from vault_engine_v2 import VaultEngine, CommandEnforcer

logger = logging.getLogger("iteration_wallet.app")

# ── Vault root — lives next to this script ──────────────────────────────────
VAULT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VaultData")


class VaultAPI:
    """
    Every public method here is callable from JavaScript as:
        window.pywebview.api.method_name(...)

    Return convention: always a plain dict, always JSON-serializable.
    Success shape:  { "ok": true,  "data": <payload> }
    Error shape:    { "ok": false, "error": "<message>" }

    The UI is responsible for rendering; the engine is responsible for state.
    """

    def __init__(self, window_ref=None):
        self._window = window_ref      # set after window creation
        self.engine = VaultEngine(VAULT_ROOT)

    def set_window(self, win):
        self._window = win

    # ── Keystroke enforcement ────────────────────────────────────────────────

    def record_keystroke(self, char: str) -> dict:
        """Called for every character typed in a command input."""
        ok, reason = self.engine.enforcer.record_keystroke(char)
        return {"ok": ok, "error": reason if not ok else ""}

    def reset_enforcer(self) -> dict:
        """Called when a command modal is closed without submitting."""
        self.engine.enforcer.reset()
        return {"ok": True}

    # ── Vault state ──────────────────────────────────────────────────────────

    def open_vault(self) -> dict:
        """
        Validate the accumulated keystrokes spell 'OPEN' then unlock.
        The enforcer has already been fed individual keystrokes by record_keystroke().
        """
        typed_ok, reason = self.engine.enforcer.validate_command("OPEN")
        if not typed_ok:
            return {"ok": False, "error": reason}
        success, msg = self.engine.open_vault(enforcer_validated=True)
        return {"ok": success, "error": "" if success else msg, "msg": msg}

    def lock_vault(self) -> dict:
        success, msg = self.engine.lock_vault()
        return {"ok": success, "msg": msg}

    def vault_state(self) -> dict:
        return {"ok": True, "data": {"open": self.engine.is_open()}}

    # ── Projects / Cradles ───────────────────────────────────────────────────

    def create_cradle(self, name: str, root_folder: str) -> dict:
        if not name or not name.strip():
            return {"ok": False, "error": "Project name is required."}
        success, msg = self.engine.create_cradle(name.strip(), root_folder.strip())
        return {"ok": success, "error": "" if success else msg, "msg": msg}

    def list_projects(self) -> dict:
        projects = self.engine.list_projects()
        return {"ok": True, "data": projects}

    def scan_cradle(self, project_name: str) -> dict:
        report = self.engine.scan_cradle(project_name)
        if "error" in report:
            return {"ok": False, "error": report["error"]}
        return {"ok": True, "data": report}

    # ── File operations ──────────────────────────────────────────────────────

    def pick_file(self) -> dict:
        """
        Open the OS native file picker dialog.
        Returns the selected path or None if cancelled.
        """
        if self._window is None:
            return {"ok": False, "error": "Window not ready."}
        try:
            result = self._window.create_file_dialog(
                webview.OPEN_DIALOG,
                allow_multiple=False
            )
            if result and len(result) > 0:
                return {"ok": True, "data": {"path": result[0]}}
            return {"ok": True, "data": {"path": None}}
        except Exception as e:
            logger.error("pick_file failed: %s", e)
            return {"ok": False, "error": str(e)}

    def add_file(self, source_path: str, project_name: str, version: str = "V1") -> dict:
        if not source_path or not source_path.strip():
            return {"ok": False, "error": "File path is required."}
        if not project_name or not project_name.strip():
            return {"ok": False, "error": "Project name is required."}
        success, msg = self.engine.add_file_to_vault(
            source_path.strip(), project_name.strip(), version.strip() or "V1"
        )
        return {"ok": success, "error": "" if success else msg, "msg": msg}

    def remove_file(self, file_id: str) -> dict:
        """
        Stage 1 of deletion: move file to holding.
        Requires REMOVE command to have been validated via enforcer first.
        """
        typed_ok, reason = self.engine.enforcer.validate_command("REMOVE")
        if not typed_ok:
            return {"ok": False, "error": reason}
        success, msg = self.engine.remove_file_from_vault(
            file_id, enforcer_validated=True
        )
        return {"ok": success, "error": "" if success else msg, "msg": msg}

    def delete_file(self, file_id: str) -> dict:
        """
        Stage 2 of deletion: permanently destroy a staged file.
        Requires DELETE command to have been validated via enforcer first.
        """
        typed_ok, reason = self.engine.enforcer.validate_command("DELETE")
        if not typed_ok:
            return {"ok": False, "error": reason}
        success, msg = self.engine.delete_file(file_id, enforcer_validated=True)
        return {"ok": success, "error": "" if success else msg, "msg": msg}

    def list_vault_files(self, project_name: str = None,
                         include_archive: bool = False) -> dict:
        files = self.engine.list_vault_files(
            project_name=project_name or None,
            include_archive=include_archive
        )
        return {"ok": True, "data": files}

    # ── Archive ──────────────────────────────────────────────────────────────

    def list_archived_versions(self, project_name: str) -> dict:
        grouped = self.engine.list_archived_versions(project_name)
        return {"ok": True, "data": grouped}

    def copy_from_vault(self, file_id: str, destination_folder: str) -> dict:
        """
        COPY — project folder side pulls a copy from vault.
        Vault entry completely untouched. Unlimited calls allowed.
        No enforcer required — non-destructive.
        """
        ok, msg = self.engine.copy_from_vault(file_id, destination_folder)
        return {"ok": ok, "message": msg}

    def release_from_vault(self, file_id: str, destination_folder: str) -> dict:
        """
        RELEASE — file physically moves OUT of vault INTO project folder.
        Vault slot empties. Enforcer must be validated first via
        record_keystroke() calls followed by validate_enforcer('RELEASE').
        """
        ok_e, msg_e = self.engine.enforcer.validate_command("RELEASE")
        if not ok_e:
            return {"ok": False, "message": f"Enforcer: {msg_e}"}
        ok, msg = self.engine.release_from_vault(file_id, destination_folder,
                                                  enforcer_validated=True)
        return {"ok": ok, "message": msg}

    def manual_archive(self, file_id: str) -> dict:
        """
        MANUAL ARCHIVE — while vault is open, push an active file
        into the archive inside the vault. Stays protected.
        Enforcer must be validated via record_keystroke() + validate_enforcer('ARCHIVE').
        """
        ok_e, msg_e = self.engine.enforcer.validate_command("ARCHIVE")
        if not ok_e:
            return {"ok": False, "message": f"Enforcer: {msg_e}"}
        ok, msg = self.engine.manual_archive(file_id, enforcer_validated=True)
        return {"ok": ok, "message": msg}

    def remove_from_archive(self, file_id: str, destination_folder: str) -> dict:
        """
        REMOVE FROM ARCHIVE — archive entry moves to project folder.
        Archive slot empties. Project folder is the only destination.
        Enforcer must be validated via record_keystroke() + validate_enforcer('REMOVE').
        """
        ok_e, msg_e = self.engine.enforcer.validate_command("REMOVE")
        if not ok_e:
            return {"ok": False, "message": f"Enforcer: {msg_e}"}
        ok, msg = self.engine.remove_from_archive(file_id, destination_folder,
                                                   enforcer_validated=True)
        return {"ok": ok, "message": msg}

    def validate_enforcer(self, command: str) -> dict:
        """
        Validate that the user has typed the command character-by-character.
        Call this after all record_keystroke() calls are done.
        Returns {"ok": bool, "message": str}
        """
        ok, msg = self.engine.enforcer.validate_command(command)
        return {"ok": ok, "message": msg}

    def restore_from_archive(self, archive_file_id: str) -> dict:
        success, msg = self.engine.restore_from_archive(archive_file_id)
        return {"ok": success, "error": "" if success else msg, "msg": msg}

    def promote_version(self, project_name: str, new_version: str) -> dict:
        if not new_version or not new_version.strip():
            return {"ok": False, "error": "New version name is required."}
        success, msg = self.engine.promote_version(
            project_name.strip(), new_version.strip()
        )
        return {"ok": success, "error": "" if success else msg, "msg": msg}

    # ── Monitor ──────────────────────────────────────────────────────────────

    def get_event_log(self, limit: int = 100) -> dict:
        events = self.engine.get_event_log(limit=limit)
        return {"ok": True, "data": events}

    def get_stats(self) -> dict:
        stats = self.engine.get_stats()
        return {"ok": True, "data": stats}

    def get_drive_status(self) -> dict:
        drives = self.engine.get_drive_status()
        return {"ok": True, "data": drives}

    def get_staged_files(self) -> dict:
        """Return all files currently in holding/staging."""
        files = self.engine.list_vault_files(include_archive=False)
        staged = [f for f in files if f["status"] == "removed"]
        return {"ok": True, "data": staged}

    # ── Full refresh ─────────────────────────────────────────────────────────

    def get_all_state(self) -> dict:
        """
        Single call to hydrate the entire UI on load or after any mutation.
        Returns vault state, projects, files, stats, recent events.
        """
        try:
            return {
                "ok": True,
                "data": {
                    "vault_open":  self.engine.is_open(),
                    "projects":    self.engine.list_projects(),
                    "files":       self.engine.list_vault_files(include_archive=True),
                    "stats":       self.engine.get_stats(),
                    "events":      self.engine.get_event_log(limit=50),
                    "drives":      self.engine.get_drive_status(),
                }
            }
        except Exception as e:
            logger.error("get_all_state failed: %s", e)
            return {"ok": False, "error": str(e)}


def start():
    api = VaultAPI()

    win = webview.create_window(
        title   = "Iteration Wallet — Rear View Foresight",
        url     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "interface.html"),
        js_api  = api,
        width   = 1280,
        height  = 820,
        min_size= (900, 600),
        background_color="#E8DCC8",   # matches --cream from CSS; no flash
    )

    api.set_window(win)

    webview.start(debug=False)


if __name__ == "__main__":
    start()
