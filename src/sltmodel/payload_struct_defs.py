"""Conditional StructLayout definitions for reassembled packet payloads."""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

from sltcalc import SltEval
from sltcodec import EnumDef, StructDef, StructLayout, TypeDict

from .resources import load_pcap_layout, load_pcapng_layout


@dataclass
class PayloadStructDef:
    """A condition and the StructLayout used when that condition matches."""

    condition: str
    struct_layout: StructLayout

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation."""
        type_dict = self.struct_layout.type_dict
        return {
            "condition": self.condition,
            "struct_layout": {
                "struct_def_name": self.struct_layout.struct_def_name,
                "type_dict": {
                    "enum_dict": {
                        key: value.to_dict()
                        for key, value in type_dict.enum_dict.items()
                    },
                    "struct_dict": {
                        key: value.to_dict()
                        for key, value in type_dict.struct_dict.items()
                    },
                },
            },
        }

    @classmethod
    def from_dict(cls, value: dict) -> "PayloadStructDef":
        """Build one conditional definition from decoded JSON data."""
        layout_data = value["struct_layout"]
        type_data = layout_data["type_dict"]
        type_dict = TypeDict(
            enum_dict={
                key: EnumDef.from_dict(item)
                for key, item in type_data.get("enum_dict", {}).items()
            },
            struct_dict={
                key: StructDef.from_dict(item)
                for key, item in type_data.get("struct_dict", {}).items()
            },
        )
        return cls(
            condition=str(value["condition"]),
            struct_layout=StructLayout(
                str(layout_data.get("struct_def_name", "")),
                type_dict,
            ),
        )


def packet_eval_env(packet) -> dict:
    """Return the sltcalc environment for a reassembled packet."""
    return {
        "key": packet.key,
        "payload": packet.data,
        "ip_version": packet.ip_version,
        "source": packet.source_bytes,
        "destination": packet.destination_bytes,
        "protocol": packet.protocol,
        "identification": packet.identification,
    }


def _enum_eval_env(enum_dict: dict) -> dict:
    """Return enum definitions in the attribute form supported by SltEval."""
    return {
        name: SimpleNamespace(**enum_def.values)
        for name, enum_def in enum_dict.items()
    }


@lru_cache(maxsize=1)
def _bundled_enum_eval_env() -> dict:
    """Return enums bundled with the PCAP and PCAPNG layouts."""
    enum_dict = {}
    for layout_loader in (load_pcap_layout, load_pcapng_layout):
        enum_dict.update(layout_loader().type_dict.enum_dict)
    return _enum_eval_env(enum_dict)


def matching_struct_layout(
    definitions: list[PayloadStructDef],
    packet,
) -> StructLayout | None:
    """Return the StructLayout from the first matching definition."""
    for definition in definitions:
        env = packet_eval_env(packet)
        env.update(_bundled_enum_eval_env())
        env.update(_enum_eval_env(definition.struct_layout.type_dict.enum_dict))
        if SltEval(env).eval(definition.condition):
            return definition.struct_layout
    return None


def load_payload_struct_defs(path: str | Path) -> list[PayloadStructDef]:
    """Load conditional payload definitions from JSON."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    definitions = data.get("payload_struct_defs", data)
    if not isinstance(definitions, list):
        raise TypeError("payload_struct_defs must be a list.")
    return [PayloadStructDef.from_dict(item) for item in definitions]


def save_payload_struct_defs(
    definitions: list[PayloadStructDef],
    path: str | Path,
) -> None:
    """Save conditional payload definitions as JSON."""
    data = {
        "payload_struct_defs":
        [definition.to_dict() for definition in definitions]
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
