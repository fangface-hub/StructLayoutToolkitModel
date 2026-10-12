"""Tests for capture packet extraction and fragment reassembly."""
import struct
from types import SimpleNamespace

import pytest
from sltcore import virtual_bytearray

from sltmodel.packet_data import (CaptureDocument, _RawFragment, _extract_ip_fragment,
                                  _extract_ipv4, _extract_ipv6, _frames,
                                  _pcap_frames, _pcapng_frames, _reassemble,
                                  _timestamp_values, internet_checksum)


def _field_instance(
    name: str,
    value: object,
    *,
    offset: int = 0,
    size: int = 0,
):
    return SimpleNamespace(
        field_def=SimpleNamespace(
            name=name,
            offset=SimpleNamespace(bytes=offset),
            size=SimpleNamespace(bytes=size),
        ),
        value=value,
    )


def _instance(*fields):
    return SimpleNamespace(field_instances=list(fields))


def _ipv4_fragment(
    payload: bytes,
    offset: int,
    more: bool,
    protocol: int = 17,
) -> bytes:
    """Create an IPv4 fragment with the given payload, offset, and more flag."""
    flags_offset = offset // 8 | (0x2000 if more else 0)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0x1234,
        flags_offset,
        64,
        protocol,
        0,
        bytes.fromhex("c0000201"),
        bytes.fromhex("c6336402"),
    )
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + header + payload


def _pcap(frames: list[bytes], link_type: int = 1) -> bytes:
    """Create a PCAP capture with the given frames."""
    result = bytearray.fromhex(
        "d4c3b2a1 0200 0400 00000000 00000000 ffff0000 01000000")
    result[20:24] = struct.pack("<I", link_type)
    for sequence, frame in enumerate(frames):
        result += struct.pack("<IIII", sequence, 0, len(frame), len(frame))
        result += frame
    return bytes(result)


def _pcapng(frames: list[bytes]) -> bytes:
    """Create a PCAPNG capture with the given frames."""
    result = bytearray.fromhex("0a0d0d0a 1c000000 4d3c2b1a 0100 0000 "
                               "ffffffffffffffff 1c000000 "
                               "01000000 14000000 0100 0000 ffff0000 14000000")
    for sequence, frame in enumerate(frames):
        padding = b"\x00" * (-len(frame) % 4)
        block_length = 32 + len(frame) + len(padding)
        result += struct.pack("<IIIIIII", 6, block_length, 0, sequence + 1,
                              sequence, len(frame), len(frame))
        result += frame + padding + struct.pack("<I", block_length)
    return bytes(result)


def _ipv6_fragment(payload: bytes, offset: int, more: bool) -> bytes:
    """Create an IPv6 fragment with the given payload, offset, and more flag."""
    source = bytes.fromhex("20010db8000000000000000000000001")
    destination = bytes.fromhex("20010db8000000000000000000000002")
    base_header = struct.pack("!IHBB16s16s", 6 << 28,
                              len(payload) + 8, 44, 64, source, destination)
    fragment_bits = offset // 8 << 3 | more
    fragment_header = struct.pack("!BBHI", 17, 0, fragment_bits, 0x12345678)
    ethernet = bytes.fromhex("00112233445566778899aabb86dd")
    return ethernet + base_header + fragment_header + payload


def test_reassembles_out_of_order_ipv4_fragments_and_writes_back():
    """Out-of-order IPv4 fragments are reassembled and writable."""
    udp_datagram = bytes.fromhex(
        "3039003500180000 0001020304050607 08090a0b0c0d0e0f")
    capture = _pcap([
        _ipv4_fragment(udp_datagram[16:], 16, False),
        _ipv4_fragment(udp_datagram[:16], 0, True),
    ])

    document = CaptureDocument.from_bytes(capture)
    packet = document.packets[0]

    assert packet.complete
    assert packet.source == "192.0.2.1"
    assert packet.destination == "198.51.100.2"
    assert packet.protocol == 17
    assert packet.timestamps == {"timestamp": "1.000000000"}
    assert packet.key == (
        4,
        bytes.fromhex("c0000201"),
        bytes.fromhex("c6336402"),
        17,
        0x1234,
    )
    assert isinstance(packet.data, virtual_bytearray)
    assert packet.data.to_bytes() == udp_datagram
    assert [(fragment.sequence, fragment.payload_offset, fragment.length,
             fragment.more_fragments) for fragment in packet.fragments] == [
                 (1, 0, 16, True),
                 (0, 16, 8, False),
             ]
    assert packet.fragments[0].timestamps["timestamp"] == "1.000000000"
    assert packet.fragments[1].timestamps["timestamp"] == "0.000000000"

    edited = bytearray(packet.data)
    edited[-4:] = b"EDIT"
    packet.replace_data(document.data, edited)

    rebuilt = bytearray(len(packet.data))
    for fragment in packet.fragments:
        rebuilt[fragment.payload_offset:fragment.payload_offset +
                fragment.length] = document.data[
                    fragment.capture_offset:fragment.capture_offset +
                    fragment.length]
    assert rebuilt == packet.data.to_bytes()
    assert rebuilt[-4:] == b"EDIT"
    assert int.from_bytes(rebuilt[6:8], "big") != 0


def test_incomplete_fragment_group_cannot_be_edited():
    """Test that an incomplete fragment group cannot be edited."""
    capture = _pcap([_ipv4_fragment(b"01234567", 0, True)])
    document = CaptureDocument.from_bytes(capture)

    assert not document.packets[0].complete
    with pytest.raises(ValueError, match="Incomplete"):
        document.packets[0].replace_data(document.data, b"abcdefgh")


def test_reassembled_packet_rejects_length_change():
    capture = _pcap([
        _ipv4_fragment(bytes.fromhex("3039003500080000"), 0, False),
    ])
    document = CaptureDocument.from_bytes(capture)

    with pytest.raises(ValueError, match="must keep the reassembled length"):
        document.packets[0].replace_data(document.data, b"short")


def test_replace_data_updates_icmp_checksum():
    payload = bytes(8)
    capture = _pcap([_ipv4_fragment(payload, 0, False, protocol=1)])
    document = CaptureDocument.from_bytes(capture)
    packet = document.packets[0]
    expected_checksum = internet_checksum(payload)

    packet.replace_data(document.data, payload)

    assert packet.data[2:4].to_bytes() == expected_checksum.to_bytes(2, "big")


def test_replace_data_updates_ipv6_udp_checksum():
    datagram = bytes.fromhex("3039003500080000")
    capture = _pcap([_ipv6_fragment(datagram, 0, False)])
    document = CaptureDocument.from_bytes(capture)
    packet = document.packets[0]

    packet.replace_data(document.data, datagram)

    assert packet.data[6:8].to_bytes() != b"\x00\x00"


def test_replace_data_leaves_unknown_protocol_unchanged():
    payload = bytes.fromhex("0001020304050607")
    capture = _pcap([_ipv4_fragment(payload, 0, False)])
    document = CaptureDocument.from_bytes(capture)
    packet = document.packets[0]
    packet.protocol = 255

    packet.replace_data(document.data, payload)

    assert packet.data.to_bytes() == payload


def test_unfragmented_packets_with_same_identification_remain_separate():
    """Unfragmented packets with the same ID remain separate."""
    datagram = bytes.fromhex("3039003500080000")
    capture = _pcap([
        _ipv4_fragment(datagram, 0, False),
        _ipv4_fragment(datagram, 0, False),
    ])

    document = CaptureDocument.from_bytes(capture)

    assert len(document.packets) == 2


def test_reassembles_ipv4_fragments_from_pcapng():
    datagram = bytes.fromhex(
        "3039003500180000 0001020304050607 08090a0b0c0d0e0f")
    capture = _pcapng([
        _ipv4_fragment(datagram[:16], 0, True),
        _ipv4_fragment(datagram[16:], 16, False),
    ])

    document = CaptureDocument.from_bytes(capture)

    assert document.capture_format == "pcapng"
    assert document.packets[0].complete
    assert document.packets[0].data.to_bytes() == datagram
    assert document.packets[0].timestamps == {"timestamp": 1 << 32}


def test_capture_timestamps_use_decode_transform():
    capture = _pcap([
        _ipv4_fragment(bytes.fromhex("3039003500080000"), 0, False),
    ])

    def transform(instance):
        record = instance.get_field("record[0]").value
        timestamp = record.get_field("pcap_timestamp").value
        for index, field in enumerate(timestamp.field_instances):
            if field.field_def.name == "timestamp_seconds":
                timestamp.field_instances[index] = field.with_value(
                    "transformed")
        return instance

    document = CaptureDocument.from_bytes(capture, transform)

    assert document.packets[0].timestamps["timestamp"] == "transformed"


def test_reassembles_out_of_order_ipv6_fragments():
    datagram = bytes.fromhex(
        "3039003500180000 0001020304050607 08090a0b0c0d0e0f")
    capture = _pcap([
        _ipv6_fragment(datagram[16:], 16, False),
        _ipv6_fragment(datagram[:16], 0, True),
    ])

    document = CaptureDocument.from_bytes(capture)
    packet = document.packets[0]

    assert packet.complete
    assert packet.ip_version == 6
    assert packet.source == "2001:db8::1"
    assert packet.destination == "2001:db8::2"
    assert packet.data.to_bytes() == datagram


def test_reassembled_data_is_a_writable_view_of_capture_data():
    datagram = bytes.fromhex(
        "3039003500180000 0001020304050607 08090a0b0c0d0e0f")
    document = CaptureDocument.from_bytes(
        _pcap([
            _ipv4_fragment(datagram[:16], 0, True),
            _ipv4_fragment(datagram[16:], 16, False),
        ]))
    packet = document.packets[0]
    first_fragment = packet.fragments[0]

    packet.data.write_byte(8, 0xFF)

    assert document.data[first_fragment.capture_offset + 8] == 0xFF


def test_capture_document_keeps_mutable_input_without_copying():
    capture = bytearray(
        _pcap([_ipv4_fragment(bytes.fromhex("3039003500080000"), 0, False)]))

    document = CaptureDocument.from_bytes(capture)

    assert document.data is capture


def test_capture_document_rejects_unsupported_format():
    with pytest.raises(ValueError, match="not a supported PCAP"):
        CaptureDocument.from_bytes(b"not a capture")


def test_capture_document_opens_and_saves_files(tmp_path):
    capture = _pcap([
        _ipv4_fragment(bytes.fromhex("3039003500080000"), 0, False),
    ])
    source = tmp_path / "source.pcap"
    destination = tmp_path / "destination.pcap"
    source.write_bytes(capture)

    document = CaptureDocument.open(source)
    document.save(destination)

    assert destination.read_bytes() == capture


def test_internet_checksum_pads_odd_length_data():
    assert internet_checksum(bytes.fromhex("010203")) == 0xFBFD


@pytest.mark.parametrize("capture_format, factory, frame_offset", [
    ("pcap", _pcap, 40),
    ("pcapng", _pcapng, 76),
])
def test_frame_metadata_comes_from_decoded_fields(capture_format, factory,
                                                  frame_offset):
    frame = _ipv4_fragment(bytes.fromhex("3039003500080000"), 0, False)
    document = CaptureDocument.from_bytes(factory([frame]))

    frames = _frames(document.struct_instance, capture_format)
    assert [frame[:4] for frame in frames] == [
        (frame_offset, len(frame), 1, {
            "timestamp": "0.000000000"
        } if capture_format == "pcap" else {
            "timestamp": 1 << 32
        }),
    ]


def test_capture_document_reports_decode_and_reassembly_progress():
    """Capture decoding and fragment reassembly report one progress stream."""
    capture = _pcap([
        _ipv4_fragment(b"01234567", 0, True),
        _ipv4_fragment(b"89ABCDEF", 8, False),
    ])
    updates = []

    CaptureDocument.from_bytes(capture, progress_callback=updates.append)

    assert updates
    assert updates == sorted(updates)
    assert any(0.0 < progress < 0.7 for progress in updates)
    assert any(0.7 <= progress < 1.0 for progress in updates)
    assert updates[-1] == 1.0


def test_empty_capture_completes_progress_without_packets():
    updates = []

    document = CaptureDocument.from_bytes(_pcap([]),
                                          progress_callback=updates.append)

    assert document.packets == []
    assert updates[-1] == 1.0


def test_timestamp_values_supports_display_values_and_raw_fields():
    pcap_timestamp = _instance(
        _field_instance("timestamp_seconds", 12),
        _field_instance("timestamp_nanoseconds", 34),
    )
    displayed_timestamp = _instance()
    displayed_timestamp.display_value = "formatted"
    raw_timestamp = _instance(
        _field_instance("high", 2),
        _field_instance("low", 3),
    )
    text_timestamp = _instance(
        _field_instance("high", "raw timestamp"),
        _field_instance("low", 0),
    )
    text_seconds_timestamp = _instance(
        _field_instance("timestamp_seconds", "raw seconds"),
        _field_instance("timestamp_nanoseconds", 0),
    )
    displayed_pcap_timestamp = _instance()
    displayed_pcap_timestamp.display_value = "displayed pcap time"

    assert _timestamp_values((
        _field_instance("pcap_timestamp", pcap_timestamp),
        _field_instance("pcap_timestamp", displayed_pcap_timestamp),
        _field_instance("timestamp", displayed_timestamp),
        _field_instance("timestamp", raw_timestamp),
        _field_instance("pcap_timestamp", text_seconds_timestamp),
        _field_instance("timestamp", text_timestamp),
        _field_instance("timestamp_resolution", 9),
        _field_instance("ignored", 10),
    )) == {
        "timestamp": "raw timestamp",
        "timestamp_resolution": 9,
    }


def test_pcap_frames_handles_missing_header_and_skips_non_packet_records():
    assert _pcap_frames(_instance()) == []

    header = _instance(_field_instance("link_type", 0x10001))
    packet_data = _field_instance("packet_data", b"frame", offset=4, size=5)
    packet_record = _field_instance(
        "record[0]",
        _instance(packet_data),
        offset=16,
    )
    ignored_record = _field_instance(
        "trailer",
        _instance(_field_instance("packet_data", b"ignored")),
    )
    no_packet_record = _field_instance("record[1]", _instance())

    assert _pcap_frames(_instance(
        _field_instance("header", header),
        ignored_record,
        no_packet_record,
        packet_record,
    )) == [(20, 5, 1, {}, b"frame")]


def test_pcapng_frames_handles_interface_blocks_packet_blocks_and_resets():
    def block(*fields, offset=0):
        return _field_instance(
            "block",
            _instance(*fields),
            offset=offset,
        )

    interface_body = _instance(
        _field_instance("link_type", 1),
        _field_instance("snap_len", 10),
    )
    interface_block = block(
        _field_instance("body", interface_body, offset=8),
    )
    packet_body = _instance(
        _field_instance("interface_id", 0),
        _field_instance("packet_data", b"enhanced", offset=4, size=8),
    )
    enhanced_block = block(
        _field_instance("body", packet_body, offset=8),
        offset=20,
    )
    invalid_interface_block = block(
        _field_instance(
            "body",
            _instance(
                _field_instance("interface_id", 3),
                _field_instance("packet_data", b"ignored", size=7),
            ),
        ),
    )
    simple_packet_block = block(
        _field_instance(
            "body",
            _instance(
                _field_instance("original_packet_length", 12),
                _field_instance(
                    "packet_data_with_padding",
                    b"simple!!!",
                    offset=4,
                    size=9,
                ),
            ),
            offset=8,
        ),
        offset=40,
    )
    irrelevant_block = block(_field_instance("body", _instance()))
    reset_block = block(
        _field_instance("byte_order_magic", b"\x4d\x3c\x2b\x1a"),
        _field_instance(
            "body",
            _instance(
                _field_instance("original_packet_length", 3),
                _field_instance("packet_data_with_padding", b"abc", size=3),
            ),
        ),
    )
    no_body_block = block(_field_instance("not_body", None))

    frames = _pcapng_frames(_instance(
        no_body_block,
        simple_packet_block,
        interface_block,
        invalid_interface_block,
        enhanced_block,
        irrelevant_block,
        simple_packet_block,
        reset_block,
        simple_packet_block,
    ))

    assert frames == [
        (32, 8, 1, {}, b"enhanced"),
        (52, 9, 1, {}, b"simple!!!"),
    ]


def test_extract_ip_fragment_ignores_unsupported_links_and_network_packets():
    packet_data = _instance()
    assert _extract_ip_fragment(
        bytearray(100), 0, 100, 0, 0, {}, packet_data) is None
    assert _extract_ip_fragment(
        bytearray(100), 0, 100, 1, 0, {}, packet_data) is None

    unsupported_packet = _instance(_field_instance("other_header", 1))
    ethernet_data = _instance(
        _field_instance("network_packet", unsupported_packet, offset=14),
    )
    assert _extract_ip_fragment(
        bytearray(100), 0, 100, 1, 0, {}, ethernet_data) is None

    missing_transport_ipv4 = _instance(
        _field_instance("version_ihl", 0x45),
    )
    ethernet_ipv4 = _instance(
        _field_instance(
            "network_packet",
            missing_transport_ipv4,
            offset=14,
        ),
    )
    assert _extract_ip_fragment(
        bytearray(100), 0, 100, 1, 0, {}, ethernet_ipv4) is None
    assert _extract_ipv4(bytearray(100), 14, 0, {}, missing_transport_ipv4) \
        is None

    missing_transport_ipv6 = _instance(
        _field_instance("version_traffic_flow", 6 << 28),
    )
    assert _extract_ipv6(bytearray(100), 14, 0, {}, missing_transport_ipv6) \
        is None


def test_extract_ip_fragment_rejects_unrecognized_network_header(monkeypatch):
    monkeypatch.setattr(
        "sltmodel.packet_data._network_packet",
        lambda _packet_data: (SimpleNamespace(field_instances=[]), 14),
    )

    assert _extract_ip_fragment(
        bytearray(100),
        0,
        100,
        1,
        0,
        {},
        _instance(),
    ) is None


def test_extract_unfragmented_ipv6_packet_without_fragment_header():
    capture = bytearray(100)
    capture[54:62] = b"payload!"
    packet = _instance(
        _field_instance("version_traffic_flow", 6 << 28),
        _field_instance("next_header", 17),
        _field_instance("source_address", bytes(16)),
        _field_instance("destination_address", bytes(16)),
        _field_instance(
            "transport_segment",
            b"payload!",
            offset=40,
            size=8,
        ),
    )

    fragment = _extract_ipv6(
        capture,
        14,
        5,
        {},
        packet,
    )

    assert fragment is not None
    assert fragment.key == (6, 5)
    assert fragment.identification is None
    assert fragment.offset == 0
    assert not fragment.more_fragments
    assert fragment.data.to_bytes() == b"payload!"


def test_ipv6_fragment_header_without_payload_is_ignored():
    fragment_header = _instance()
    packet = _instance(
        _field_instance("next_header", 44),
        _field_instance(
            "transport_segment",
            fragment_header,
            offset=40,
        ),
    )

    assert _extract_ipv6(bytearray(100), 14, 0, {}, packet) is None


def test_capture_with_non_ethernet_link_type_has_no_ip_packets():
    document = CaptureDocument.from_bytes(
        _pcap([_ipv4_fragment(b"01234567", 0, False)], link_type=101),
    )

    assert document.packets == []


def test_reassemble_preserves_first_data_for_overlaps_and_zero_fills_gaps():
    key = (4, b"source", b"destination", 17, 9)

    def fragment(sequence, offset, data, more):
        return _RawFragment(
            sequence,
            {},
            key,
            4,
            b"source",
            b"destination",
            17,
            9,
            offset,
            more,
            sequence,
            virtual_bytearray((data,)),
        )

    progress = []
    overlap = _reassemble([
        fragment(1, 0, b"abcdefgh", True),
        fragment(0, 4, b"XXXXXXXX", False),
    ], progress.append)[0]
    duplicate_overlap = _reassemble([
        fragment(3, 0, b"abcdefgh", True),
        fragment(4, 0, b"XXXXXXXX", False),
    ])[0]
    gap = _reassemble([
        fragment(2, 8, b"tail", False),
    ])[0]

    assert overlap.complete
    assert overlap.data.to_bytes() == b"abcdefghXXXX"
    assert [part.sequence for part in overlap.fragments] == [1, 0]
    assert progress == [1.0]
    assert duplicate_overlap.complete
    assert duplicate_overlap.data.to_bytes() == b"abcdefgh"
    assert not gap.complete
    assert gap.data.to_bytes() == bytes(8) + b"tail"
    assert gap.fragments[0].length == 4


def test_internet_checksum_handles_empty_input_and_replace_short_data():
    assert internet_checksum(b"") == 0xFFFF

    payload = b"short"
    document = CaptureDocument.from_bytes(
        _pcap([_ipv4_fragment(payload, 0, False)]),
    )
    packet = document.packets[0]
    packet.replace_data(document.data, packet.data)
    packet.replace_data(document.data, payload)

    assert packet.data.to_bytes() == payload
