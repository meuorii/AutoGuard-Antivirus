"""Add three harmless AutoGuard test fixtures and merge their signatures.

Run from the project root:
    python tools/setup_autoguard_test_signatures.py

This script creates Downloads/AutoGuard-Test in the current user's home folder,
backs up data/signatures.json, and merges the test entries without deleting
existing configured signatures. These are simulated detections, not viruses.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SIGNATURES_PATH = PROJECT_ROOT / "data" / "signatures.json"
TEST_DIR = Path.home() / "Downloads" / "AutoGuard-Test"

FIXTURES = (
    ("AG-TEST-001.txt", b"AUTOGUARD-SIMULATED-TEST-FIXTURE-001\n"),
    ("AG-TEST-002.txt", b"AUTOGUARD-SIMULATED-TEST-FIXTURE-002\n"),
    ("AG-TEST-003.txt", b"AUTOGUARD-SIMULATED-TEST-FIXTURE-003\n"),
)


def main() -> None:
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    SIGNATURES_PATH.parent.mkdir(parents=True, exist_ok=True)

    if SIGNATURES_PATH.exists():
        try:
            payload = json.loads(SIGNATURES_PATH.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SystemExit(f"Cannot safely read {SIGNATURES_PATH}: {error}") from error
        if (
            not isinstance(payload, dict)
            or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1
            or not isinstance(payload.get("signatures"), list)
        ):
            raise SystemExit(
                "Existing signatures.json has an unexpected format; it was not changed."
            )
    else:
        payload = {"schema_version": 1, "signatures": []}

    entries = payload["signatures"]
    existing_hashes = {
        str(item.get("sha256", "")).lower()
        for item in entries
        if isinstance(item, dict)
    }
    additions = []

    for filename, content in FIXTURES:
        fixture_path = TEST_DIR / filename
        fixture_path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()

        if digest not in existing_hashes:
            additions.append({
                "name": f"AutoGuard Simulated Test {filename.removesuffix('.txt')}",
                "sha256": digest,
                "kind": "autoguard_test",
                "description": (
                    "Harmless local fixture used to verify AutoGuard signature "
                    "detection; this is not real malware."
                ),
            })
            existing_hashes.add(digest)

        print(f"Created: {fixture_path}")
        print(f"SHA-256: {digest}")

    if additions:
        if SIGNATURES_PATH.exists():
            backup = SIGNATURES_PATH.with_suffix(".json.bak")
            counter = 1
            while backup.exists():
                backup = SIGNATURES_PATH.with_suffix(f".json.bak{counter}")
                counter += 1
            backup.write_text(
                SIGNATURES_PATH.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            print(f"Backup: {backup}")

        entries.extend(additions)
        SIGNATURES_PATH.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Added {len(additions)} test signature(s) to: {SIGNATURES_PATH}")
    else:
        print("All three test signatures already exist; signatures.json was unchanged.")

    print("\nRestart AutoGuard, then scan this folder:")
    print(TEST_DIR)
    print("\nThese files should be reported as simulated test detections.")


if __name__ == "__main__":
    main()
