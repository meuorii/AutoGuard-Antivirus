"""Small, version-independent UI preference store in the configured data folder."""
import json
from pathlib import Path

TEXT_SIZES = ("Standard", "Large", "Extra Large")


def load_text_size(data_dir: Path) -> str:
    try:
        value = json.loads((data_dir / "ui-settings.json").read_text(encoding="utf-8")).get("text_size")
        return value if value in TEXT_SIZES else "Large"
    except (OSError, ValueError, AttributeError, UnicodeError):
        return "Large"


def save_text_size(data_dir: Path, value: str) -> None:
    if value not in TEXT_SIZES:
        raise ValueError("Unknown text size")
    path = data_dir / "ui-settings.json"
    data_dir.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"text_size": value}), encoding="utf-8")
    temporary.replace(path)
