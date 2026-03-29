"""
Iteration Wallet — Vault Engine v2
===================================
"Let find something right where YOU left it."

© 2025 Rear View Foresight LLC — Josie Curtsey Cobbley

CHANGES FROM v1
---------------
[CRITICAL] Watcher now RESTORES files — not just detects, but reverses.
[CRITICAL] SQLite WAL mode + persistent connection + threading.Lock.
[CRITICAL] Silent exception handlers replaced with event logging.
[HIGH]     MD5+time file ID replaced with uuid4.
[HIGH]     Checksums recomputed at version promotion (not inherited).
[HIGH]     Staging garbage collection — REMOVED files >30 days auto-purged.
[HIGH]     Vault backup copy stored at add-time for reliable restoration.
[MEDIUM]   Drive monitor detection hardened.
[MEDIUM]   All DB operations through single _db() context manager.
"""

import os
import stat
import uuid
import shutil
import hashlib
import threading
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
from contextlib import contextmanager

import sqlite3


# ─────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("iteration_wallet")


# ─────────────────────────────────────────────────────────────
#  Constants & Enums
# ─────────────────────────────────────────────────────────────

VAULT_DB_NAME        = "vault.db"
VAULT_CONTAINER_DIR  = ".vault_container"
VAULT_BACKUP_DIR     = ".vault_backup"       # clean copies for restoration
ARCHIVE_DIR          = ".vault_archive"
STAGING_DIR          = ".vault_staging"
WATCH_INTERVAL       = 1.0                   # seconds
STAGING_MAX_AGE_DAYS = 30                    # auto-purge REMOVED files older than this


class VaultState(Enum):
    LOCKED = "locked"
    OPEN   = "open"


class FileStatus(Enum):
    VAULT_PROTECTED = "vault_protected"
    REMOVED         = "removed"
    ARCHIVED        = "archived"
    WORKING_COPY    = "working_copy"


# ─────────────────────────────────────────────────────────────
#  Data classes
# ─────────────────────────────────────────────────────────────

@dataclass
class VaultFile:
    file_id:       str
    original_path: str
    vault_path:    str
    backup_path:   str          # clean copy for watcher restoration
    checksum:      str
    status:        str
    project_name:  str
    version:       str
    created_at:    str
    updated_at:    str
    is_archive:    bool = False


@dataclass
class CradleProject:
    project_id:  str
    name:        str
    root_folder: str
    created_at:  str
    file_count:  int = 0


# ─────────────────────────────────────────────────────────────
#  Command Enforcer
#  Heart of the security model.
#  Typed commands only. No paste. No automation bypass.
# ─────────────────────────────────────────────────────────────

class CommandEnforcer:
    """
    Validates that commands are typed character-by-character
    within human-realistic timing windows.

    Security model: stops accidents, slows automated tools,
    creates mandatory friction for every destructive action.
    Not designed to stop a determined attacker with root access.
    """

    MIN_CHAR_INTERVAL = 0.05    # 50 ms  — faster = automation
    MAX_CHAR_INTERVAL = 10.0    # 10 sec — longer = session timeout

    def __init__(self):
        self._lock = threading.Lock()
        self._keystroke_times: List[float] = []
        self._typed_chars:     List[str]   = []

    def reset(self):
        with self._lock:
            self._keystroke_times = []
            self._typed_chars     = []

    def record_keystroke(self, char: str) -> Tuple[bool, str]:
        """
        Record one keystroke. Returns (ok, reason).
        Returns False if timing suggests automation.
        """
        now = time.monotonic()
        with self._lock:
            if self._keystroke_times:
                interval = now - self._keystroke_times[-1]
                if interval < self.MIN_CHAR_INTERVAL:
                    self._reset_locked()
                    return False, "Typing too fast — automation detected."
                if interval > self.MAX_CHAR_INTERVAL:
                    self._reset_locked()
                    return False, "Session timed out. Start again."
            self._keystroke_times.append(now)
            self._typed_chars.append(char)
        return True, ""

    def validate_command(self, expected: str) -> Tuple[bool, str]:
        """
        Returns (True, "") only if:
          1. Characters match expected command exactly.
          2. All timing checks passed on input.
          3. Command is ALL CAPS.
          4. At least len(expected) keystrokes recorded.
        """
        with self._lock:
            typed = "".join(self._typed_chars)
            n     = len(self._keystroke_times)
            self._reset_locked()

        if typed != expected:
            return False, f'Command must be exactly "{expected}".'
        if typed != typed.upper():
            return False, "Command must be ALL CAPS."
        if n < len(expected):
            return False, "Type each character individually."
        return True, ""

    def _reset_locked(self):
        self._keystroke_times = []
        self._typed_chars     = []


# ─────────────────────────────────────────────────────────────
#  Vault Engine
# ─────────────────────────────────────────────────────────────

class VaultEngine:

    def __init__(self, vault_root: str):
        self.vault_root     = Path(vault_root).resolve()
        self.container_path = self.vault_root / VAULT_CONTAINER_DIR
        self.backup_path    = self.vault_root / VAULT_BACKUP_DIR
        self.archive_path   = self.vault_root / ARCHIVE_DIR
        self.staging_path   = self.vault_root / STAGING_DIR
        self.db_path        = self.vault_root / VAULT_DB_NAME

        self.state          = VaultState.LOCKED
        self.enforcer       = CommandEnforcer()

        self._db_lock       = threading.RLock()   # RLock: reentrant — watcher calls _db() while holding _db_lock
        self._conn: Optional[sqlite3.Connection] = None

        self._watching      = False
        self._watcher_thread: Optional[threading.Thread] = None

        self._init_directories()
        self._open_database()
        self._init_schema()
        self._start_file_watcher()

    # ─────────────────────────────────────────
    #  Initialisation
    # ─────────────────────────────────────────

    def _init_directories(self):
        for d in [self.vault_root, self.container_path, self.backup_path,
                  self.archive_path, self.staging_path]:
            d.mkdir(parents=True, exist_ok=True)

        # Hide internal dirs on Windows
        try:
            import subprocess
            for d in [self.container_path, self.backup_path,
                      self.archive_path, self.staging_path]:
                subprocess.run(["attrib", "+h", str(d)], capture_output=True)
        except Exception:
            pass

    def _open_database(self):
        """Open persistent WAL-mode connection. Called once at startup."""
        conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None       # autocommit; we manage transactions
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        self._conn = conn

    def _init_schema(self):
        with self._db() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS vault_files (
                    file_id       TEXT PRIMARY KEY,
                    original_path TEXT NOT NULL,
                    vault_path    TEXT NOT NULL,
                    backup_path   TEXT NOT NULL DEFAULT '',
                    checksum      TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    project_name  TEXT NOT NULL,
                    version       TEXT NOT NULL DEFAULT 'V1',
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL,
                    is_archive    INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS cradle_projects (
                    project_id  TEXT PRIMARY KEY,
                    name        TEXT NOT NULL UNIQUE,
                    root_folder TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    file_count  INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS vault_events (
                    event_id   TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    file_id    TEXT,
                    description TEXT,
                    timestamp  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vf_project
                    ON vault_files(project_name, is_archive);
                CREATE INDEX IF NOT EXISTS idx_vf_status
                    ON vault_files(status);
                CREATE INDEX IF NOT EXISTS idx_ve_ts
                    ON vault_events(timestamp DESC);
            """)

    @contextmanager
    def _db(self):
        """Thread-safe database cursor context manager."""
        with self._db_lock:
            c = self._conn.cursor()
            try:
                c.execute("BEGIN")
                yield c
                self._conn.commit()
            except Exception as e:
                self._conn.rollback()
                logger.error("DB error: %s", e)
                raise

    def close(self):
        self.stop_watcher()
        if self._conn:
            self._conn.close()

    # ─────────────────────────────────────────
    #  State management
    # ─────────────────────────────────────────

    def open_vault(self, enforcer_validated: bool = False) -> Tuple[bool, str]:
        if not enforcer_validated:
            return False, "OPEN command must be typed manually. No shortcuts."
        if self.state == VaultState.OPEN:
            return False, "Vault is already open."
        self.state = VaultState.OPEN
        self._log_event("VAULT_OPENED", None, "Vault manually opened.")
        return True, "Vault is now OPEN."

    def lock_vault(self) -> Tuple[bool, str]:
        self.state = VaultState.LOCKED
        self._log_event("VAULT_LOCKED", None, "Vault locked.")
        return True, "Vault locked."

    def is_open(self) -> bool:
        return self.state == VaultState.OPEN

    # ─────────────────────────────────────────
    #  File operations
    # ─────────────────────────────────────────

    def add_file_to_vault(self, source_path: str, project_name: str,
                          version: str = "V1") -> Tuple[bool, str]:
        """
        Add file to vault.
        Creates protected working copy AND a separate backup copy for restoration.
        """
        source = Path(source_path).resolve()
        if not source.exists():
            return False, f"File not found: {source_path}"
        if not source.is_file():
            return False, f"Not a file: {source_path}"

        try:
            file_id  = self._new_id()
            checksum = self._checksum(source)

            # Working copy
            proj_dir = self.container_path / project_name
            proj_dir.mkdir(parents=True, exist_ok=True)
            vault_file = proj_dir / f"{file_id}_{source.name}"
            shutil.copy2(source, vault_file)
            self._set_readonly(vault_file, True)

            # Backup copy — used by watcher for restoration
            bk_dir = self.backup_path / project_name
            bk_dir.mkdir(parents=True, exist_ok=True)
            backup_file = bk_dir / f"{file_id}_{source.name}.bak"
            shutil.copy2(source, backup_file)
            self._set_readonly(backup_file, True)

            now = self._now()
            with self._db() as c:
                c.execute(
                    """INSERT OR REPLACE INTO vault_files
                       (file_id, original_path, vault_path, backup_path,
                        checksum, status, project_name, version,
                        created_at, updated_at, is_archive)
                       VALUES (?,?,?,?,?,?,?,?,?,?,0)""",
                    (file_id, str(source), str(vault_file), str(backup_file),
                     checksum, FileStatus.VAULT_PROTECTED.value,
                     project_name, version, now, now)
                )
                # Update cradle file count
                c.execute(
                    """UPDATE cradle_projects
                       SET file_count = file_count + 1
                       WHERE name = ?""",
                    (project_name,)
                )

            self._log_event("FILE_ADDED", file_id,
                            f"Added {source.name} to project '{project_name}'")
            return True, f"✓ {source.name} added to Vault under project '{project_name}'"

        except Exception as e:
            logger.error("add_file_to_vault failed: %s", e)
            return False, f"Failed to add file: {e}"

    def remove_file_from_vault(self, file_id: str,
                                enforcer_validated: bool = False) -> Tuple[bool, str]:
        """
        Step 1 of deletion: move file out of active vault to staging.
        File remains tracked and can still be restored until DELETE.
        """
        if not self.is_open():
            return False, "Vault must be OPEN first. Type OPEN to access."
        if not enforcer_validated:
            return False, "REMOVE command must be typed manually."

        try:
            f = self._get_file(file_id)
            if not f:
                return False, f"File ID {file_id} not found in vault."
            if f["is_archive"]:
                return False, "Cannot remove archived files directly."
            if f["status"] == FileStatus.REMOVED.value:
                return False, "File is already in staging (REMOVED)."

            vault_path   = Path(f["vault_path"])
            staging_file = self.staging_path / vault_path.name

            self._set_readonly(vault_path, False)
            shutil.move(str(vault_path), staging_file)

            now = self._now()
            with self._db() as c:
                c.execute(
                    """UPDATE vault_files
                       SET status=?, vault_path=?, updated_at=?
                       WHERE file_id=?""",
                    (FileStatus.REMOVED.value, str(staging_file), now, file_id)
                )

            self._log_event("FILE_REMOVED", file_id,
                            "File moved to staging. Pending DELETE.")
            return True, ("✓ File removed from Vault. "
                          "Still protected in staging. Use DELETE to finalise.")

        except Exception as e:
            logger.error("remove_file_from_vault failed: %s", e)
            return False, f"Failed to remove file: {e}"

    def delete_file(self, file_id: str,
                    enforcer_validated: bool = False) -> Tuple[bool, str]:
        """
        Step 2 of deletion: permanently destroy a REMOVED file.
        Also removes its backup copy.
        """
        if not enforcer_validated:
            return False, "DELETE command must be typed manually in ALL CAPS."

        try:
            f = self._get_file(file_id)
            if not f:
                return False, f"File ID {file_id} not found."
            if f["status"] != FileStatus.REMOVED.value:
                return False, "File must be REMOVED from vault before DELETE."

            # Delete staging copy
            staging_path = Path(f["vault_path"])
            if staging_path.exists():
                staging_path.unlink()

            # Delete backup copy
            backup_path = Path(f["backup_path"])
            if backup_path.exists():
                self._set_readonly(backup_path, False)
                backup_path.unlink()

            with self._db() as c:
                c.execute("DELETE FROM vault_files WHERE file_id=?", (file_id,))
                c.execute(
                    """UPDATE cradle_projects
                       SET file_count = MAX(0, file_count - 1)
                       WHERE name = ?""",
                    (f["project_name"],)
                )

            self._log_event("FILE_DELETED", file_id,
                            "File permanently deleted and backup removed.")
            return True, "✓ File permanently deleted."

        except Exception as e:
            logger.error("delete_file failed: %s", e)
            return False, f"Failed to delete file: {e}"

    # ─────────────────────────────────────────
    #  Cradle management
    # ─────────────────────────────────────────

    def create_cradle(self, project_name: str,
                      root_folder: str) -> Tuple[bool, str]:
        if not project_name.strip():
            return False, "Project name cannot be empty."
        try:
            project_id = self._new_id()
            now        = self._now()
            with self._db() as c:
                c.execute(
                    """INSERT INTO cradle_projects
                       (project_id, name, root_folder, created_at, file_count)
                       VALUES (?,?,?,?,0)""",
                    (project_id, project_name.strip(), root_folder, now)
                )
            (self.container_path / project_name).mkdir(exist_ok=True)
            self._log_event("CRADLE_CREATED", None,
                            f"Cradle created for project '{project_name}'")
            return True, f"✓ Cradle created: '{project_name}'"
        except sqlite3.IntegrityError:
            return False, f"A project named '{project_name}' already exists."
        except Exception as e:
            logger.error("create_cradle failed: %s", e)
            return False, f"Failed to create cradle: {e}"

    def scan_cradle(self, project_name: str) -> Dict:
        cradle = self._get_cradle(project_name)
        if not cradle:
            return {"error": f"No cradle found for project '{project_name}'"}

        root = Path(cradle["root_folder"])
        if not root.exists():
            return {"error": f"Project folder not found: {root}"}

        report = {
            "project":         project_name,
            "scanned_at":      self._now(),
            "new_files":       [],
            "changed_files":   [],
            "unchanged_files": [],
            "total_files":     0,
        }

        vault_files = self._get_project_files(project_name)
        vault_index = {f["original_path"]: f for f in vault_files}

        for fp in root.rglob("*"):
            if not fp.is_file() or self._is_internal(fp):
                continue
            report["total_files"] += 1
            cs  = self._checksum(fp)
            key = str(fp)
            if key not in vault_index:
                report["new_files"].append({"path": key, "name": fp.name, "checksum": cs})
            elif vault_index[key]["checksum"] != cs:
                report["changed_files"].append({
                    "path":           key,
                    "name":           fp.name,
                    "current_checksum": cs,
                    "vault_checksum": vault_index[key]["checksum"],
                })
            else:
                report["unchanged_files"].append(fp.name)

        return report

    # ─────────────────────────────────────────
    #  Version management & Archive District
    # ─────────────────────────────────────────

    def promote_version(self, project_name: str,
                        new_version: str) -> Tuple[bool, str]:
        """
        Promote working copies to new version.
        Archive old version with full protection.
        Checksums recomputed at promotion time — not inherited.
        """
        current_files = self._get_project_files(project_name)
        if not current_files:
            return False, f"No active files found for project '{project_name}'"

        current_version = current_files[0]["version"]
        archive_dir     = self.archive_path / project_name / current_version
        archive_dir.mkdir(parents=True, exist_ok=True)

        try:
            for f in current_files:
                vault_path = Path(f["vault_path"])
                if not vault_path.exists():
                    continue

                # Archive copy
                arch_file = archive_dir / vault_path.name
                shutil.copy2(vault_path, arch_file)
                self._set_readonly(arch_file, True)

                # Backup for archive
                arch_bk_dir  = self.backup_path / project_name / current_version
                arch_bk_dir.mkdir(parents=True, exist_ok=True)
                arch_bk_file = arch_bk_dir / (vault_path.name + ".bak")
                shutil.copy2(vault_path, arch_bk_file)
                self._set_readonly(arch_bk_file, True)

                # Recompute checksum from actual bytes — never inherit
                fresh_checksum = self._checksum(arch_file)

                now        = self._now()
                archive_id = self._new_id()
                with self._db() as c:
                    c.execute(
                        """INSERT OR REPLACE INTO vault_files
                           (file_id, original_path, vault_path, backup_path,
                            checksum, status, project_name, version,
                            created_at, updated_at, is_archive)
                           VALUES (?,?,?,?,?,?,?,?,?,?,1)""",
                        (archive_id, f["original_path"], str(arch_file),
                         str(arch_bk_file), fresh_checksum,
                         FileStatus.ARCHIVED.value, project_name,
                         current_version, f["created_at"], now)
                    )

            # Update active files to new version
            now = self._now()
            with self._db() as c:
                c.execute(
                    """UPDATE vault_files
                       SET version=?, updated_at=?
                       WHERE project_name=? AND is_archive=0""",
                    (new_version, now, project_name)
                )

            self._log_event("VERSION_PROMOTED", None,
                            f"'{project_name}': {current_version} → {new_version}")
            return True, (f"✓ Version promoted: "
                          f"{current_version} → {new_version}. Previous version archived.")

        except Exception as e:
            logger.error("promote_version failed: %s", e)
            return False, f"Promotion failed: {e}"

    def copy_from_vault(self, file_id: str,
                        destination_folder: str) -> Tuple[bool, str]:
        """
        COPY — initiated from the project folder side.

        Pulls a copy of a vault-protected or archived file into the
        destination folder (the project folder).  The vault entry is
        completely untouched.  This operation may be called unlimited
        times; each copy receives a unique stamped name so copies
        never collide on disk.

        No enforcer required — COPY is non-destructive.
        Vault must be OPEN.
        """
        if not self.is_open():
            return False, "Vault must be OPEN to copy from it. Type OPEN."

        try:
            f = self._get_file(file_id)
            if not f:
                return False, f"File ID {file_id} not found in vault."
            if f["status"] not in (FileStatus.VAULT_PROTECTED.value,
                                   FileStatus.ARCHIVED.value):
                return False, "Only protected or archived files can be copied."

            src  = Path(f["vault_path"])
            if not src.exists():
                return False, f"Vault file missing on disk: {src.name}"

            dest_dir = Path(destination_folder).resolve()
            dest_dir.mkdir(parents=True, exist_ok=True)

            # Unique copy name: original_name_COPY_<4-char-id>.ext
            stem = src.stem.split("_", 1)[-1] if "_" in src.stem else src.stem
            suffix = src.suffix
            copy_id = self._new_id()[:4].upper()
            dest = dest_dir / f"{stem}_COPY_{copy_id}{suffix}"

            shutil.copy2(src, dest)
            # Copy is writable — it's in the project folder now, user's territory
            self._set_readonly(dest, False)

            self._log_event(
                "FILE_COPIED", file_id,
                f"Copied vault v{f['version']} → {dest.name} in {dest_dir.name}"
                f" — vault original untouched"
            )
            return True, (f"✓ Copy {dest.name} placed in project folder. "
                          f"Vault original unchanged.")

        except Exception as e:
            logger.error("copy_from_vault failed: %s", e)
            return False, f"Copy failed: {e}"

    def release_from_vault(self, file_id: str,
                           destination_folder: str,
                           enforcer_validated: bool = False) -> Tuple[bool, str]:
        """
        RELEASE — the file physically moves OUT of the vault INTO the project folder.

        The vault canonical slot (or archive slot) becomes EMPTY after this
        operation.  The file exists only in the project folder afterward.
        This is a deliberate, irreversible removal from vault protection.

        Rules:
        - Vault must be OPEN.
        - Enforcer must be validated (user typed RELEASE keystroke-by-keystroke).
        - Only VAULT_PROTECTED or ARCHIVED files may be released.
        - After release the DB record is removed; the file is no longer tracked.
        """
        if not self.is_open():
            return False, "Vault must be OPEN to release from it. Type OPEN."
        if not enforcer_validated:
            return False, "RELEASE command must be typed manually, character by character."

        try:
            f = self._get_file(file_id)
            if not f:
                return False, f"File ID {file_id} not found in vault."
            if f["status"] not in (FileStatus.VAULT_PROTECTED.value,
                                   FileStatus.ARCHIVED.value):
                return False, "Only protected or archived files can be released."

            vault_path = Path(f["vault_path"])
            if not vault_path.exists():
                return False, f"Vault file missing on disk: {vault_path.name}"

            dest_dir = Path(destination_folder).resolve()
            dest_dir.mkdir(parents=True, exist_ok=True)

            stem   = vault_path.stem.split("_", 1)[-1] if "_" in vault_path.stem else vault_path.stem
            suffix = vault_path.suffix
            dest   = dest_dir / f"{stem}_RELEASED{suffix}"

            # Make writable so it can be moved
            self._set_readonly(vault_path, False)
            shutil.move(str(vault_path), dest)
            self._set_readonly(dest, False)

            # Remove backup — it belonged to the vault copy which no longer exists
            backup_path = Path(f["backup_path"])
            if backup_path.exists():
                self._set_readonly(backup_path, False)
                backup_path.unlink()

            # Remove DB record — file is no longer vault-tracked
            with self._db() as c:
                c.execute("DELETE FROM vault_files WHERE file_id=?", (file_id,))
                if not f["is_archive"]:
                    c.execute(
                        "UPDATE cradle_projects SET file_count = MAX(0, file_count-1) WHERE name=?",
                        (f["project_name"],)
                    )

            self._log_event(
                "FILE_RELEASED", file_id,
                f"RELEASED v{f['version']} → {dest.name} in {dest_dir.name}"
                f" — vault slot now EMPTY"
            )
            return True, (f"✓ {dest.name} moved to project folder. "
                          f"Vault slot is now empty.")

        except Exception as e:
            logger.error("release_from_vault failed: %s", e)
            return False, f"Release failed: {e}"

    def manual_archive(self, file_id: str,
                       enforcer_validated: bool = False) -> Tuple[bool, str]:
        """
        MANUAL ARCHIVE — user explicitly moves an active vault file
        down into the Archive while the vault is open.

        The file stays inside the vault — it moves from the Cradle
        (active canonical) to the Archive directory.  Still protected.
        Still read-only.  Still tracked.  The watcher covers it.

        Rules:
        - Vault must be OPEN.
        - Enforcer must be validated (user typed ARCHIVE keystroke-by-keystroke).
        - Only VAULT_PROTECTED (active) files may be manually archived.
          Files already in archive cannot be re-archived.
        """
        if not self.is_open():
            return False, "Vault must be OPEN. Type OPEN."
        if not enforcer_validated:
            return False, "ARCHIVE command must be typed manually, character by character."

        try:
            f = self._get_file(file_id)
            if not f:
                return False, f"File ID {file_id} not found."
            if f["status"] != FileStatus.VAULT_PROTECTED.value:
                return False, "Only active vault files can be manually archived."
            if f["is_archive"]:
                return False, "File is already in the archive."

            vault_path = Path(f["vault_path"])
            if not vault_path.exists():
                return False, f"Vault file missing on disk: {vault_path.name}"

            arch_dir = self.archive_path / f["project_name"] / f["version"]
            arch_dir.mkdir(parents=True, exist_ok=True)

            arch_file = arch_dir / vault_path.name
            self._set_readonly(vault_path, False)
            shutil.move(str(vault_path), arch_file)
            self._set_readonly(arch_file, True)

            # Archive backup
            arch_bk_dir = self.backup_path / f["project_name"] / f["version"]
            arch_bk_dir.mkdir(parents=True, exist_ok=True)
            arch_bk = arch_bk_dir / (arch_file.name + ".bak")
            shutil.copy2(arch_file, arch_bk)
            self._set_readonly(arch_bk, True)

            # Remove old backup (belonged to container path slot)
            old_bk = Path(f["backup_path"])
            if old_bk.exists():
                self._set_readonly(old_bk, False)
                old_bk.unlink()

            now = self._now()
            with self._db() as c:
                c.execute(
                    """UPDATE vault_files
                       SET status=?, vault_path=?, backup_path=?,
                           is_archive=1, updated_at=?
                       WHERE file_id=?""",
                    (FileStatus.ARCHIVED.value, str(arch_file),
                     str(arch_bk), now, file_id)
                )
                c.execute(
                    "UPDATE cradle_projects SET file_count=MAX(0,file_count-1) WHERE name=?",
                    (f["project_name"],)
                )

            self._log_event(
                "FILE_MANUALLY_ARCHIVED", file_id,
                f"{vault_path.name} moved to archive v{f['version']} — still inside vault"
            )
            return True, f"✓ File archived inside vault. Still protected."

        except Exception as e:
            logger.error("manual_archive failed: %s", e)
            return False, f"Manual archive failed: {e}"

    def remove_from_archive(self, file_id: str,
                            destination_folder: str,
                            enforcer_validated: bool = False) -> Tuple[bool, str]:
        """
        REMOVE FROM ARCHIVE — moves an archived file OUT of the vault
        INTO the project folder.  The archive slot becomes empty.

        This is functionally identical to RELEASE but operates on
        archive entries rather than active canonical files.
        The project folder is the only destination.  Always.

        Rules:
        - Vault must be OPEN.
        - Enforcer must be validated (user typed REMOVE keystroke-by-keystroke).
        - File must have is_archive=1 and status=ARCHIVED.
        - After removal the DB record is deleted; file is no longer vault-tracked.
        """
        if not self.is_open():
            return False, "Vault must be OPEN. Type OPEN."
        if not enforcer_validated:
            return False, "REMOVE command must be typed manually, character by character."

        try:
            f = self._get_file(file_id)
            if not f:
                return False, f"File ID {file_id} not found."
            if not f["is_archive"] or f["status"] != FileStatus.ARCHIVED.value:
                return False, "File is not an archived vault entry."

            arch_path = Path(f["vault_path"])
            if not arch_path.exists():
                return False, f"Archive file missing on disk: {arch_path.name}"

            dest_dir = Path(destination_folder).resolve()
            dest_dir.mkdir(parents=True, exist_ok=True)

            stem   = arch_path.stem.split("_", 1)[-1] if "_" in arch_path.stem else arch_path.stem
            suffix = arch_path.suffix
            dest   = dest_dir / f"{stem}_FROM_ARCHIVE_v{f['version']}{suffix}"

            self._set_readonly(arch_path, False)
            shutil.move(str(arch_path), dest)
            self._set_readonly(dest, False)

            # Remove archive backup
            bk = Path(f["backup_path"])
            if bk.exists():
                self._set_readonly(bk, False)
                bk.unlink()

            with self._db() as c:
                c.execute("DELETE FROM vault_files WHERE file_id=?", (file_id,))

            self._log_event(
                "ARCHIVE_REMOVED", file_id,
                f"REMOVED from archive v{f['version']} → {dest.name} in {dest_dir.name}"
                f" — archive slot now EMPTY"
            )
            return True, (f"✓ {dest.name} moved to project folder from archive. "
                          f"Archive slot is now empty.")

        except Exception as e:
            logger.error("remove_from_archive failed: %s", e)
            return False, f"Remove from archive failed: {e}"

    def restore_from_archive(self, archive_file_id: str) -> Tuple[bool, str]:
        """Restore an archived version back to active status."""
        try:
            f = self._get_file(archive_file_id)
            if not f or not f["is_archive"]:
                return False, "Archive record not found."

            src = Path(f["vault_path"])
            if not src.exists():
                return False, "Archive file missing on disk."

            # Copy back to container
            proj_dir   = self.container_path / f["project_name"]
            proj_dir.mkdir(exist_ok=True)
            new_id     = self._new_id()
            dest       = proj_dir / f"{new_id}_{src.name.split('_', 1)[-1]}"
            shutil.copy2(src, dest)
            self._set_readonly(dest, True)

            # New backup
            bk_dir   = self.backup_path / f["project_name"]
            bk_dir.mkdir(exist_ok=True)
            bk_file  = bk_dir / (dest.name + ".bak")
            shutil.copy2(src, bk_file)
            self._set_readonly(bk_file, True)

            checksum = self._checksum(dest)
            now      = self._now()
            with self._db() as c:
                c.execute(
                    """INSERT INTO vault_files
                       (file_id, original_path, vault_path, backup_path,
                        checksum, status, project_name, version,
                        created_at, updated_at, is_archive)
                       VALUES (?,?,?,?,?,?,?,?,?,?,0)""",
                    (new_id, f["original_path"], str(dest), str(bk_file),
                     checksum, FileStatus.VAULT_PROTECTED.value,
                     f["project_name"], f["version"] + "_restored", now, now)
                )

            self._log_event("ARCHIVE_RESTORED", archive_file_id,
                            f"Restored from archive version {f['version']}")
            return True, f"✓ Restored from archive version {f['version']}"

        except Exception as e:
            logger.error("restore_from_archive failed: %s", e)
            return False, f"Restore failed: {e}"

    # ─────────────────────────────────────────
    #  File Watcher — ransomware / AI protection
    # ─────────────────────────────────────────

    def _start_file_watcher(self):
        self._watching       = True
        self._watcher_thread = threading.Thread(
            target=self._watch_loop, daemon=True, name="vault-watcher"
        )
        self._watcher_thread.start()

    def _watch_loop(self):
        while self._watching:
            try:
                self._verify_vault_integrity()
                self._purge_stale_staging()
            except Exception as e:
                logger.error("Watcher cycle error: %s", e)
            time.sleep(WATCH_INTERVAL)

    def _verify_vault_integrity(self):
        """
        Check all protected/archived files against stored checksums.
        On modification: restore from backup immediately.
        On deletion:     log alert and attempt restore from backup.
        """
        try:
            with self._db_lock:
                c = self._conn.cursor()
                c.execute(
                    """SELECT * FROM vault_files
                       WHERE status IN (?,?)""",
                    (FileStatus.VAULT_PROTECTED.value, FileStatus.ARCHIVED.value)
                )
                files = [dict(r) for r in c.fetchall()]
        except Exception as e:
            logger.error("Integrity check query failed: %s", e)
            return

        for f in files:
            vault_path  = Path(f["vault_path"])
            backup_path = Path(f["backup_path"])

            if not vault_path.exists():
                # File missing — attempt restore from backup
                self._log_event(
                    "INTEGRITY_VIOLATION", f["file_id"],
                    f"ALERT: Vault file missing: {vault_path.name}. Attempting restore."
                )
                if backup_path.exists():
                    try:
                        vault_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(backup_path, vault_path)
                        self._set_readonly(vault_path, True)
                        self._log_event(
                            "FILE_RESTORED", f["file_id"],
                            f"Restored missing file from backup: {vault_path.name}"
                        )
                    except Exception as e:
                        logger.error("Restore-missing failed %s: %s", vault_path.name, e)
                        self._log_event(
                            "RESTORE_FAILED", f["file_id"],
                            f"Could not restore {vault_path.name}: {e}"
                        )
                continue

            try:
                current = self._checksum(vault_path)
            except Exception as e:
                logger.error("Checksum failed for %s: %s", vault_path, e)
                continue

            if current != f["checksum"]:
                self._log_event(
                    "INTEGRITY_VIOLATION", f["file_id"],
                    f"ALERT: Unauthorized modification: {vault_path.name}. Restoring."
                )
                if backup_path.exists():
                    try:
                        self._set_readonly(vault_path, False)
                        shutil.copy2(backup_path, vault_path)
                        self._set_readonly(vault_path, True)
                        self._log_event(
                            "FILE_RESTORED", f["file_id"],
                            f"Modification reversed: {vault_path.name}"
                        )
                    except Exception as e:
                        logger.error("Restore-modified failed %s: %s", vault_path.name, e)
                        self._log_event(
                            "RESTORE_FAILED", f["file_id"],
                            f"Could not reverse modification in {vault_path.name}: {e}"
                        )
                else:
                    # No backup — re-lock and alert
                    try:
                        self._set_readonly(vault_path, True)
                    except Exception:
                        pass
                    self._log_event(
                        "RESTORE_UNAVAILABLE", f["file_id"],
                        f"No backup available for {vault_path.name}. File re-locked."
                    )

    def _purge_stale_staging(self):
        """
        Remove REMOVED files from staging that are older than STAGING_MAX_AGE_DAYS.
        Prevents staging directory filling the drive indefinitely.
        """
        cutoff = datetime.now() - timedelta(days=STAGING_MAX_AGE_DAYS)
        try:
            with self._db_lock:
                c = self._conn.cursor()
                c.execute(
                    "SELECT * FROM vault_files WHERE status=?",
                    (FileStatus.REMOVED.value,)
                )
                stale = [
                    dict(r) for r in c.fetchall()
                    if datetime.fromisoformat(r["updated_at"]) < cutoff
                ]
        except Exception as e:
            logger.error("Stale staging query failed: %s", e)
            return

        for f in stale:
            try:
                p = Path(f["vault_path"])
                if p.exists():
                    p.unlink()
                with self._db() as c:
                    c.execute("DELETE FROM vault_files WHERE file_id=?", (f["file_id"],))
                self._log_event(
                    "STAGING_PURGED", f["file_id"],
                    f"Staging file auto-purged after {STAGING_MAX_AGE_DAYS} days."
                )
            except Exception as e:
                logger.error("Staging purge failed for %s: %s", f["file_id"], e)

    def stop_watcher(self):
        self._watching = False

    # ─────────────────────────────────────────
    #  Drive monitor
    # ─────────────────────────────────────────

    def get_drive_status(self) -> List[Dict]:
        """
        Return list of drives and whether they carry Vault data.
        Detection only — does not prevent formatting.
        """
        drives = []
        if os.name == "nt":
            import string
            for letter in string.ascii_uppercase:
                path = Path(f"{letter}:\\")
                if path.exists():
                    has_vault = (path / VAULT_CONTAINER_DIR).exists()
                    drives.append({
                        "letter":    letter + ":\\",
                        "has_vault": has_vault,
                        "warning":   has_vault,
                    })
        else:
            # Unix: scan /proc/mounts or just return current vault
            drives.append({
                "letter":    str(self.vault_root),
                "has_vault": True,
                "warning":   False,
            })
        return drives

    # ─────────────────────────────────────────
    #  Query helpers
    # ─────────────────────────────────────────

    def list_projects(self) -> List[Dict]:
        with self._db_lock:
            c = self._conn.cursor()
            c.execute("SELECT * FROM cradle_projects ORDER BY created_at DESC")
            return [dict(r) for r in c.fetchall()]

    def list_vault_files(self, project_name: str = None,
                         include_archive: bool = False) -> List[Dict]:
        with self._db_lock:
            c = self._conn.cursor()
            if project_name and not include_archive:
                c.execute(
                    "SELECT * FROM vault_files WHERE project_name=? AND is_archive=0 ORDER BY created_at",
                    (project_name,)
                )
            elif project_name:
                c.execute(
                    "SELECT * FROM vault_files WHERE project_name=? ORDER BY is_archive, created_at",
                    (project_name,)
                )
            else:
                c.execute("SELECT * FROM vault_files ORDER BY project_name, created_at")
            return [dict(r) for r in c.fetchall()]

    def list_archived_versions(self, project_name: str) -> Dict:
        """Return archive entries grouped by version."""
        with self._db_lock:
            c = self._conn.cursor()
            c.execute(
                """SELECT * FROM vault_files
                   WHERE project_name=? AND is_archive=1
                   ORDER BY version, created_at""",
                (project_name,)
            )
            rows = [dict(r) for r in c.fetchall()]

        grouped: Dict[str, List] = {}
        for r in rows:
            grouped.setdefault(r["version"], []).append(r)
        return grouped

    def get_event_log(self, limit: int = 100) -> List[Dict]:
        with self._db_lock:
            c = self._conn.cursor()
            c.execute(
                "SELECT * FROM vault_events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return [dict(r) for r in c.fetchall()]

    def get_stats(self) -> Dict:
        with self._db_lock:
            c = self._conn.cursor()
            c.execute("SELECT COUNT(*) FROM cradle_projects")
            projects = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM vault_files WHERE is_archive=0 AND status=?",
                      (FileStatus.VAULT_PROTECTED.value,))
            protected = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM vault_files WHERE is_archive=1")
            archived = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM vault_events")
            events = c.fetchone()[0]
        return {
            "projects":  projects,
            "protected": protected,
            "archived":  archived,
            "events":    events,
        }

    # ─────────────────────────────────────────
    #  Internal utilities
    # ─────────────────────────────────────────

    @staticmethod
    def _new_id() -> str:
        """Cryptographically random 12-char ID. No MD5. No time seed."""
        return uuid.uuid4().hex[:12]

    @staticmethod
    def _checksum(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _set_readonly(path: Path, readonly: bool):
        try:
            if readonly:
                path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
            else:
                path.chmod(stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH)
        except Exception as e:
            logger.warning("chmod failed on %s: %s", path, e)

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat(timespec="seconds")

    def _is_internal(self, path: Path) -> bool:
        internal = {
            VAULT_CONTAINER_DIR, VAULT_BACKUP_DIR, ARCHIVE_DIR, STAGING_DIR,
            VAULT_DB_NAME, "__pycache__", ".git"
        }
        return any(part in internal for part in path.parts)

    def _get_file(self, file_id: str) -> Optional[Dict]:
        with self._db_lock:
            c = self._conn.cursor()
            c.execute("SELECT * FROM vault_files WHERE file_id=?", (file_id,))
            row = c.fetchone()
        return dict(row) if row else None

    def _get_cradle(self, project_name: str) -> Optional[Dict]:
        with self._db_lock:
            c = self._conn.cursor()
            c.execute("SELECT * FROM cradle_projects WHERE name=?", (project_name,))
            row = c.fetchone()
        return dict(row) if row else None

    def _get_project_files(self, project_name: str,
                           include_archive: bool = False) -> List[Dict]:
        with self._db_lock:
            c = self._conn.cursor()
            if include_archive:
                c.execute(
                    "SELECT * FROM vault_files WHERE project_name=?",
                    (project_name,)
                )
            else:
                c.execute(
                    "SELECT * FROM vault_files WHERE project_name=? AND is_archive=0",
                    (project_name,)
                )
            return [dict(r) for r in c.fetchall()]

    def _log_event(self, event_type: str, file_id: Optional[str], desc: str):
        try:
            with self._db() as c:
                c.execute(
                    """INSERT INTO vault_events
                       (event_id, event_type, file_id, description, timestamp)
                       VALUES (?,?,?,?,?)""",
                    (self._new_id(), event_type, file_id, desc, self._now())
                )
        except Exception as e:
            # Last resort — if even logging fails, write to stderr
            logger.error("FAILED TO LOG EVENT %s: %s | cause: %s",
                         event_type, desc, e)
