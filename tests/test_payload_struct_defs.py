"""Tests for conditional packet payload StructLayout definitions."""
import json
import types

import pytest
from sltcodec import StructLayout, TypeDict

from sltmodel.payload_struct_defs import (PayloadStructDef,
                                          load_payload_struct_defs,
                                          matching_struct_layout,
                                          packet_eval_env,
                                          save_payload_struct_defs)
from sltmodel.resources import load_pcap_layout, load_pcapng_layout


def _packet(**overrides):
    values = {
        "key": (4, b"source", b"destination", 17, 0x1234),
        "ip_version": 4,
        "source_bytes": b"source",
        "destination_bytes": b"destination",
        "protocol": 17,
        "identification": 0x1234,
        "data": bytearray.fromhex("30390035"),
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def test_packet_eval_env_exposes_reassembly_key_and_payload():
    packet = _packet()

    env = packet_eval_env(packet)

    assert env["key"] is packet.key
    assert env["payload"] is packet.data
    assert env["protocol"] == 17
    assert env["identification"] == 0x1234


def test_matching_struct_layout_uses_first_matching_condition():
    tcp_layout = StructLayout("tcp", TypeDict())
    udp_layout = StructLayout("udp", TypeDict())
    definitions = [
        PayloadStructDef("protocol == 17 and payload[0] == 0x30", udp_layout),
        PayloadStructDef("True", tcp_layout),
    ]

    assert matching_struct_layout(definitions, _packet()) is udp_layout
    assert (matching_struct_layout(definitions, _packet(protocol=6))
            is tcp_layout)


def test_matching_struct_layout_returns_none_when_no_condition_matches():
    definitions = [
        PayloadStructDef("protocol == 6", StructLayout("tcp", TypeDict())),
    ]

    assert matching_struct_layout(definitions, _packet(protocol=17)) is None


@pytest.mark.parametrize(
    "layout_loader, condition",
    [
        (load_pcap_layout, "EtherType.IPV4 == 2048"),
        (load_pcapng_layout, "IpProtocol.UDP == protocol"),
    ],
)
def test_matching_struct_layout_exposes_resource_enums(layout_loader,
                                                       condition):
    layout = layout_loader()
    definition = PayloadStructDef(condition, layout)

    assert matching_struct_layout([definition], _packet()) is layout


def test_matching_struct_layout_exposes_bundled_enums_without_layout_enums():
    layout = StructLayout("payload", TypeDict())
    definition = PayloadStructDef("EtherType.IPV4 == 2048", layout)

    assert matching_struct_layout([definition], _packet()) is layout


def test_payload_struct_definitions_round_trip_json(tmp_path):
    path = tmp_path / "payload_struct_defs.json"
    definitions = [
        PayloadStructDef("key[3] == 17", StructLayout("udp", TypeDict())),
    ]

    save_payload_struct_defs(definitions, path)
    loaded = load_payload_struct_defs(path)

    assert loaded[0].condition == "key[3] == 17"
    assert loaded[0].struct_layout.struct_def_name == "udp"
    assert not loaded[0].struct_layout.type_dict.struct_dict


def test_load_payload_struct_defs_rejects_non_list_value(tmp_path):
    path = tmp_path / "payload_struct_defs.json"
    path.write_text(json.dumps({"payload_struct_defs": {}}), encoding="utf-8")

    with pytest.raises(TypeError, match="must be a list"):
        load_payload_struct_defs(path)
