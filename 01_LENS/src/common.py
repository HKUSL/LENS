from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any


EVAL_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(EVAL_SRC_DIR)
DEFAULT_SEED_EXAMPLES_FILE = os.path.join(
    EVAL_DIR, "data", "diameter", "seed_examples.md"
)
DEFAULT_SPECS_DIR = os.path.join(EVAL_DIR, "data", "specs")


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def write_text(path: str, text: str) -> None:
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def write_json(path: str, data: Any) -> None:
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def file_ready(path: str, min_size: int = 20) -> bool:
    return os.path.exists(path) and os.path.getsize(path) >= min_size

