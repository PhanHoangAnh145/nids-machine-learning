"""Run: python src/view_crypto_logs.py

Print locally decrypted alert logs. Do not publicly post the output if it contains
sensitive network metadata.
"""
import json
from crypto_logger import SecureAlertLogger

logger = SecureAlertLogger()
events = logger.read_all()
print(f"Records: {len(events)}")
for event in events[-10:]:
    print(json.dumps(event, ensure_ascii=False, indent=2))
