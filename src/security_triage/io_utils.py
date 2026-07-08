from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class DataFormatError(ValueError):
    pass


def load_structured_file(path: str | Path) -> Any:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if not text.strip():
        return None
    if file_path.suffix.lower() == ".json":
        return json.loads(text)
    if file_path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise DataFormatError(
                f"YAML fixture {file_path} requires PyYAML; use JSON or install security-triage[yaml]"
            ) from exc
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise DataFormatError(
                f"Could not parse {file_path} as JSON and PyYAML is not installed"
            ) from exc
        return yaml.safe_load(text)


def write_json_file(path: str | Path, data: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )


def write_yaml_file(path: str | Path, data: Any) -> None:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise DataFormatError(
            "YAML output requires PyYAML; choose --format json or install the yaml extra"
        ) from exc
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
