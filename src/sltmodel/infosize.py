"""Shared InfoSize parsing/formatting helpers used by the editor windows.

These take the caller's InfoSize class as a parameter instead of importing
one directly, so callers (and their tests) can supply their own InfoSize
implementation without this module caching a stale class reference.
"""
from __future__ import annotations

import json


def format_infosize(value: object) -> str:
    """Format an InfoSize-like value as its ``byte,bit`` string form."""
    return f"{value.byte},{value.bit}"


def parse_infosize_input(value: object, info_size_cls: type) -> object:
    """Parse ``byte,bit`` input, preserving non-static expressions."""
    if isinstance(value, info_size_cls):
        return value
    if isinstance(value, dict) and value.get("__type__") == "InfoSize":
        return info_size_cls(int(value.get("byte", 0)), int(value.get("bit",
                                                                      0)))
    text = str(value).strip()
    if not text:
        text = "0,0"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and parsed.get("__type__") == "InfoSize":
        return info_size_cls(int(parsed.get("byte", 0)),
                             int(parsed.get("bit", 0)))
    parts = [part.strip() for part in text.split(",")]
    if len(parts) == 1:
        try:
            return info_size_cls(int(parts[0]), 0)
        except ValueError:
            return text
    if len(parts) == 2:
        try:
            byte, bit = (int(part) for part in parts)
        except ValueError:
            return text
        return info_size_cls(byte, bit)
    return text


def infosize_value_to_string(value: object, info_size_cls: type) -> str:
    """Convert an InfoSize-like value to one editable cell string."""

    def from_dict(item: dict) -> str:
        info_size = info_size_cls(int(item.get("byte", 0)),
                                  int(item.get("bit", 0)))
        return format_infosize(info_size)

    def from_string(item: str) -> str:
        stripped = item.strip()
        if not stripped:
            return "0,0"
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            try:
                info_size = info_size_cls(int(stripped), 0)
            except ValueError:
                return stripped
            return format_infosize(info_size)
        if isinstance(parsed, dict) and parsed.get("__type__") == "InfoSize":
            return from_dict(parsed)
        return stripped

    if isinstance(value, info_size_cls):
        return format_infosize(value)

    handlers = {
        dict:
        lambda item: from_dict(item)
        if item.get("__type__") == "InfoSize" else "0,0",
        str:
        from_string,
        int:
        lambda item: from_dict({
            "byte": item,
            "bit": 0
        }),
    }
    return handlers.get(type(value), lambda _: "0,0")(value)


def infosize_to_json_data(value: object) -> dict:
    """Convert an InfoSize-like instance to its typed JSON dictionary."""
    return json.loads(value.serialize())
