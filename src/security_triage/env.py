from __future__ import annotations

import os
import re
from pathlib import Path

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_dotenv(path: str | Path = ".env", override: bool = False) -> dict[str, str]:
    """Load simple KEY=VALUE pairs from a .env file into os.environ.

    Existing environment variables win by default so shell exports, CI secrets,
    and GitHub Actions environment values keep precedence over local files.
    """
    env_path = Path(path)
    if not env_path.exists():
        return {}
    loaded: dict[str, str] = {}
    for line_number, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), start=1):
        parsed = _parse_dotenv_line(raw_line)
        if parsed is None:
            continue
        key, value = parsed
        if not _KEY_RE.match(key):
            raise ValueError(f"Invalid .env variable name on line {line_number}: {key}")
        if override or key not in os.environ:
            os.environ[key] = value
            loaded[key] = value
    return loaded


def _parse_dotenv_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()
    if "=" not in stripped:
        return None
    key, value = stripped.split("=", 1)
    key = key.strip()
    value = _strip_inline_comment(value.strip())
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return key, value


def _strip_inline_comment(value: str) -> str:
    quote: str | None = None
    for index, character in enumerate(value):
        if character in {'"', "'"}:
            if quote == character:
                quote = None
            elif quote is None:
                quote = character
        if character == "#" and quote is None and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value
