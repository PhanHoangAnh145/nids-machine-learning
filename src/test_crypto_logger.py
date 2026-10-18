"""Run: python src/test_crypto_logger.py"""
import base64
import json
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from crypto_logger import SecureAlertLogger

with tempfile.TemporaryDirectory() as directory:
    base = Path(directory)
    logger = SecureAlertLogger(
        log_path=base / "alerts.enc.jsonl",
        key_path=base / "aes256.key",
    )
    logger.append_alert({"kind": "single_alert", "category": "dos", "confidence": 0.97})
    events = logger.read_all()
    assert len(events) == 1
    assert events[0]["category"] == "dos"
    print("PASS: AES-256-GCM encryption and decryption")

    envelope = json.loads(logger.log_path.read_text(encoding="utf-8").splitlines()[0])
    changed = bytearray(base64.b64decode(envelope["ciphertext"]))
    changed[0] ^= 1
    envelope["ciphertext"] = base64.b64encode(changed).decode("ascii")
    try:
        logger.decrypt_record(envelope)
    except InvalidTag:
        print("PASS: modified ciphertext was rejected")
    else:
        raise AssertionError("Tampering was not detected")

    assert "dos" not in logger.log_path.read_text(encoding="utf-8")
    print("PASS: raw log does not contain plaintext attack category")

print("All crypto module tests passed.")
