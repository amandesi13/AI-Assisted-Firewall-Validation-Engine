from __future__ import annotations

import json
from pathlib import Path

from .models import Policy


def load_policy(path: str | Path) -> Policy:
    policy_path = Path(path)
    with policy_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("policy file must contain a JSON object")
    return Policy.from_dict(data)
