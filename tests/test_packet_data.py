"""Tests for capture packet extraction and fragment reassembly."""
import struct

import pytest
from sltcore import virtual_bytearray

from sltmodel.packet_data import (CaptureDocument, _frames,
                                  internet_checksum)


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


def _pcap(frames: list[bytes]) -> bytes:
    """Create a PCAP capture with the given frames."""
    result = bytearray.fromhex(
        "d4c3b2a1 0200 0400 00000000 00000000 ffff0000 01000000")
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
