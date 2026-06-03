"""JSON manifest loading helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toolkit.models import MergeRequest


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_merge_request(path: str | Path) -> MergeRequest:
    return MergeRequest.from_dict(load_json(path))
