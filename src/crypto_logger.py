"""AES-256-GCM encryption for NIDS alert records.

The application key lives under the current OS user's home directory, OUTSIDE
of the Git repository. This is a teaching/demo module, not a centralized SIEM.
"""

import base64
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "alerts.enc.jsonl"
DEFAULT_KEY_PATH = Path.home() / ".nids_shield" / "aes256.key"
AAD = b"NIDS-SHIELD-ALERT-v1"


class SecureAlertLogger:
    """Encrypt, append and verify individual JSON alert records."""

    def __init__(self, log_path=None, key_path=None):
        self.log_path = Path(log_path) if log_path is not None else DEFAULT_LOG_PATH
        self.key_path = Path(key_path) if key_path is not None else DEFAULT_KEY_PATH
        self._lock = threading.Lock()
        self._key = self._load_or_create_key()
        self._aes = AESGCM(self._key)

    def _load_or_create_key(self):
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            try:
                with self.key_path.open("xb") as file:
                    file.write(AESGCM.generate_key(bit_length=256))
                if os.name == "posix":
                    self.key_path.chmod(0o600)
            except FileExistsError:
                pass  # Created by another process in the meantime.
        key = self.key_path.read_bytes()
        if len(key) != 32:
            raise ValueError("Invalid AES-256 key: expected 32 bytes")
        return key

    def append_alert(self, event: dict) -> None:
        """Write a timestamped, encrypted NIDS event (JSON-compatible values)."""
        if not isinstance(event, dict):
            raise TypeError("event must be a dictionary")
        payload = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), **event}
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)  # Fresh 96-bit nonce per encryption.
        ciphertext = self._aes.encrypt(nonce, raw, AAD)
        envelope = {
            "version": 1,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.log_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(envelope, separators=(",", ":")) + "\n")

    def decrypt_record(self, envelope: dict) -> dict:
        """Raise InvalidTag if the secret key, nonce or ciphertext is wrong."""
        if envelope.get("version") != 1:
            raise ValueError("Unknown log record version")
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(nonce) != 12:
            raise ValueError("Invalid nonce length")
        raw = self._aes.decrypt(nonce, ciphertext, AAD)
        return json.loads(raw.decode("utf-8"))

    def read_all(self) -> list[dict]:
        """Decrypt all records. Fail on a corrupted/tampered record."""
        if not self.log_path.exists():
            return []
        events = []
        with self._lock, self.log_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                if not line.strip():
                    continue
                try:
                    events.append(self.decrypt_record(json.loads(line)))
                except (InvalidTag, ValueError, KeyError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        f"Log record {line_number} is invalid, altered or has the wrong key"
                    ) from exc
        return events
