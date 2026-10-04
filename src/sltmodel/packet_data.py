"""Capture packet extraction and IP fragment reassembly."""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sltcodec import decode
from sltcore import virtual_bytearray

from .resources import load_pcap_layout, load_pcapng_layout


@dataclass(frozen=True)
class PacketFragment:
    """Location of one IP payload fragment in the capture file."""

    sequence: int
    timestamps: dict[str, object]
    capture_offset: int
    payload_offset: int
    length: int
    more_fragments: bool


@dataclass
class ReassembledPacket:
    """One complete or partial reassembled IP payload."""

    sequence: int
    timestamps: dict[str, object]
    key: tuple
    ip_version: int
    source_bytes: bytes
    destination_bytes: bytes
    protocol: int
    identification: int | None
    fragments: list[PacketFragment]
    data: virtual_bytearray
    complete: bool

    @property
    def source(self) -> str:
        """Return the source IP address as a string."""
        return str(ipaddress.ip_address(self.source_bytes))

    @property
    def destination(self) -> str:
        """Return the destination IP address as a string."""
        return str(ipaddress.ip_address(self.destination_bytes))

    def replace_data(
        self,
        capture_data: bytearray,
        data: bytes | bytearray | virtual_bytearray,
    ) -> None:
        """Write same-length reassembled data back to all source fragments."""
        if not self.complete:
            raise ValueError("Incomplete fragmented packets cannot be edited.")
        if len(data) != len(self.data):
            raise ValueError("Encoded data must keep the reassembled length.")

        del capture_data
        if data is not self.data:
            self.data.write_slice(0, data)
        self._update_transport_checksum(self.data)

    def _update_transport_checksum(self, data: virtual_bytearray) -> None:
        """Update the transport layer checksum for the given data."""
        checksum_offset = {6: 16, 17: 6, 1: 2, 58: 2}.get(self.protocol)
        if checksum_offset is None or len(data) < checksum_offset + 2:
            return
        data.write_slice(checksum_offset, b"\x00\x00")
        if self.protocol == 1:
            checksum_data = data
        elif self.ip_version == 4:
            checksum_data = virtual_bytearray((
                self.source_bytes,
                self.destination_bytes,
                bytes((0, self.protocol)),
                len(data).to_bytes(2, "big"),
                data,
            ))
        else:
            checksum_data = virtual_bytearray((
                self.source_bytes,
                self.destination_bytes,
                len(data).to_bytes(4, "big"),
                b"\x00\x00\x00",
                bytes((self.protocol, )),
                data,
            ))
        checksum = internet_checksum(checksum_data)
        data.write_slice(checksum_offset, checksum.to_bytes(2, "big"))


@dataclass(frozen=True)
class _RawFragment:
    """Representation of a raw IP fragment."""
    sequence: int
    timestamps: dict[str, object]
    key: tuple
    ip_version: int
    source: bytes
    destination: bytes
    protocol: int
    identification: int | None
    offset: int
    more_fragments: bool
    capture_offset: int
    data: virtual_bytearray


_Frame = tuple[int, int, int, dict[str, object], object]


class CaptureDocument:
    """Decoded capture data with reassembled IP payloads."""

    def __init__(
        self,
        data: bytes | bytearray,
        capture_format: str,
        decode_transform: Callable[[object], object] | None = None,
        *,
        progress_callback: Callable[[float], None] | None = None,
    ) -> None:
        self.data = data if isinstance(data, bytearray) else bytearray(data)
        self.capture_format = capture_format
        layout = (load_pcap_layout()
                  if capture_format == "pcap" else load_pcapng_layout())
        report_progress = progress_callback or (lambda _progress: None)
        self.struct_instance = decode(
            layout,
            self.data,
            progress_callback=lambda progress: report_progress(progress * 0.65),
        )
        if decode_transform is not None:
            self.struct_instance = decode_transform(self.struct_instance)
        report_progress(0.65)
        frames = _frames(self.struct_instance, capture_format)
        fragments = []
        for sequence, frame in enumerate(frames):
            offset, length, link_type, timestamps, packet_data = frame
            fragment = _extract_ip_fragment(
                self.data,
                offset,
                length,
                link_type,
                sequence,
                timestamps,
                packet_data,
            )
            if fragment is not None:
                fragments.append(fragment)
            report_progress(0.65 + 0.25 * (sequence + 1) / len(frames))
        report_progress(0.9)
        self.packets = _reassemble(
            fragments,
            lambda progress: report_progress(0.9 + progress * 0.1),
        )
        report_progress(1.0)

    @classmethod
    def from_bytes(
        cls,
        data: bytes | bytearray,
        decode_transform: Callable[[object], object] | None = None,
        *,
        progress_callback: Callable[[float], None] | None = None,
    ) -> "CaptureDocument":
        """Detect and decode a PCAP or PCAPNG byte stream."""
        magic = bytes(data[:4])
        if magic == b"\x0a\x0d\x0d\x0a":
            return cls(data,
                       "pcapng",
                       decode_transform,
                       progress_callback=progress_callback)
        if magic in {
                b"\xd4\xc3\xb2\xa1",
                b"\xa1\xb2\xc3\xd4",
                b"\x4d\x3c\xb2\xa1",
                b"\xa1\xb2\x3c\x4d",
        }:
            return cls(data,
                       "pcap",
                       decode_transform,
                       progress_callback=progress_callback)
        raise ValueError("The file is not a supported PCAP or PCAPNG capture.")

    @classmethod
    def open(
        cls,
        path: str | Path,
        decode_transform: Callable[[object], object] | None = None,
        *,
        progress_callback: Callable[[float], None] | None = None,
    ) -> "CaptureDocument":
        """Open a capture document from the specified file path."""
        return cls.from_bytes(
            bytearray(Path(path).read_bytes()),
            decode_transform,
            progress_callback=progress_callback,
        )

    def save(self, path: str | Path) -> None:
        """Save the capture document to the specified file path."""
        Path(path).write_bytes(self.data)


def _frames(instance: object, capture_format: str) -> list[_Frame]:
    """Extract frame metadata from decoded PCAP or PCAPNG fields."""
    if capture_format == "pcap":
        return _pcap_frames(instance)
    return _pcapng_frames(instance)


def _field(instance: object, name: str) -> object | None:
    """Return a named direct child field instance, if present."""
    return next((field for field in getattr(instance, "field_instances", ())
                 if field.field_def.name == name), None)


def _field_offset(*fields: object) -> int:
    """Return the absolute byte offset represented by nested fields."""
    return sum(field.field_def.offset.bytes for field in fields)


def _timestamp_values(fields: tuple[object, ...]) -> dict[str, object]:
    """Extract timestamp values from the direct fields of a packet record."""
    values = {}
    for field in fields:
        name = field.field_def.name
        value = field.value
        child_values = {
            child.field_def.name: child.value
            for child in getattr(value, "field_instances", ())
        }
        if name == "pcap_timestamp":
            display_value = getattr(value, "display_value", None)
            if display_value is not None:
                values["timestamp"] = display_value
            else:
                seconds = child_values["timestamp_seconds"]
                nanoseconds = child_values["timestamp_nanoseconds"]
                values["timestamp"] = (seconds if isinstance(seconds, str) else
                                       f"{seconds}.{nanoseconds:09d}")
        elif name == "timestamp":
            display_value = getattr(value, "display_value", None)
            if display_value is not None:
                values[name] = display_value
            else:
                high = child_values["high"]
                low = child_values["low"]
                values[name] = (high if isinstance(high, str) else high << 32
                                | low)
        elif name.startswith("timestamp_"):
            values[name] = value
    return values


def internet_checksum(data: bytes | bytearray | virtual_bytearray, ) -> int:
    """Compute the RFC 1071 one's-complement checksum for the given data."""
    total = 0
    high_byte = None
    for value in data:
        if high_byte is None:
            high_byte = value
        else:
            total += high_byte << 8 | value
            high_byte = None
    if high_byte is not None:
        total += high_byte << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _pcap_frames(instance: object) -> list[_Frame]:
    """Extract PCAP frame metadata from decoded fields."""
    header = _field(instance, "header")
    if header is None:
        return []
    link_type = _field(header.value, "link_type").value & 0xFFFF
    frames = []
    for record in instance.field_instances:
        if not record.field_def.name.startswith("record["):
            continue
        packet_data = _field(record.value, "packet_data")
        if packet_data is not None:
            frames.append(
                (_field_offset(record,
                               packet_data), packet_data.field_def.size.bytes,
                 link_type, _timestamp_values(record.value.field_instances),
                 packet_data.value))
    return frames


def _pcapng_frames(instance: object) -> list[_Frame]:
    """Extract PCAPNG frame metadata from decoded fields."""
    frames = []
    interfaces: list[tuple[int, int]] = []
    for block in instance.field_instances:
        if _field(block.value, "byte_order_magic") is not None:
            interfaces = []
        body = _field(block.value, "body")
        if body is None:
            continue
        link_type = _field(body.value, "link_type")
        snap_length = _field(body.value, "snap_len")
        if link_type is not None and snap_length is not None:
            interfaces.append((link_type.value, snap_length.value))
            continue
        packet_data = _field(body.value, "packet_data")
        interface_id = _field(body.value, "interface_id")
        if packet_data is not None and interface_id is not None:
            if interface_id.value < len(interfaces):
                frame_link_type, _ = interfaces[interface_id.value]
                frames.append(
                    (_field_offset(block, body, packet_data),
                     packet_data.field_def.size.bytes, frame_link_type,
                     _timestamp_values(body.value.field_instances),
                     packet_data.value))
            continue
        packet_data = _field(body.value, "packet_data_with_padding")
        original_length = _field(body.value, "original_packet_length")
        if packet_data is None or original_length is None:
            continue
        if not interfaces:
            continue
        frame_link_type, snap_length = interfaces[0]
        frames.append((_field_offset(block, body, packet_data),
                       min(original_length.value, snap_length,
                           packet_data.field_def.size.bytes), frame_link_type,
                       {}, packet_data.value))
    return frames


def _extract_ip_fragment(
    capture: bytearray,
    frame_offset: int,
    frame_length: int,
    link_type: int,
    sequence: int,
    timestamps: dict[str, object],
    packet_data: object,
) -> _RawFragment | None:
    """Extract an IP fragment from decoded Ethernet packet data."""
    del frame_length
    if link_type != 1:
        return None
    network_packet, network_offset = _network_packet(packet_data)
    if network_packet is None:
        return None
    if _field(network_packet, "version_ihl") is not None:
        return _extract_ipv4(capture, frame_offset + network_offset, sequence,
                             timestamps, network_packet)
    if _field(network_packet, "version_traffic_flow") is not None:
        return _extract_ipv6(capture, frame_offset + network_offset, sequence,
                             timestamps, network_packet)
    return None


def _network_packet(packet_data: object) -> tuple[object | None, int]:
    """Return the decoded IP packet and its offset within Ethernet data."""
    offset = 0
    current = packet_data
    while True:
        network_packet = _field(current, "network_packet")
        if network_packet is None:
            return None, offset
        offset += network_packet.field_def.offset.bytes
        current = network_packet.value
        if (_field(current, "version_ihl") is not None
                or _field(current, "version_traffic_flow") is not None):
            return current, offset


def _extract_ipv4(capture: bytearray, offset: int, sequence: int,
                  timestamps: dict[str, object],
                  packet: object) -> _RawFragment | None:
    """Extract an IPv4 fragment from decoded packet fields."""
    transport_segment = _field(packet, "transport_segment")
    if transport_segment is None:
        return None
    fragment_offset = _field(packet, "fragment_offset").value * 8
    more_fragments = bool(_field(packet, "more_fragments").value)
    protocol = _field(packet, "protocol").value
    identification = _field(packet, "identification").value
    payload_start = offset + transport_segment.field_def.offset.bytes
    return _raw_fragment(capture, sequence, timestamps, packet, 4, protocol,
                         identification, fragment_offset, more_fragments,
                         payload_start, transport_segment.field_def.size.bytes,
                         fragment_offset > 0 or more_fragments)


def _extract_ipv6(capture: bytearray, offset: int, sequence: int,
                  timestamps: dict[str, object],
                  packet: object) -> _RawFragment | None:
    """Extract an IPv6 fragment from decoded packet fields."""
    transport_segment = _field(packet, "transport_segment")
    if transport_segment is None:
        return None
    if _field(packet, "next_header").value == 44:
        fragment_header = transport_segment.value
        payload_field = _field(fragment_header, "fragment_payload")
        if payload_field is None:
            return None
        protocol = _field(fragment_header, "next_header").value
        fragment_offset = _field(fragment_header, "fragment_offset").value * 8
        more_field = _field(fragment_header, "more_fragments")
        more_fragments = bool(more_field.value)
        identification = _field(fragment_header, "identification").value
        payload_start = (offset + transport_segment.field_def.offset.bytes +
                         payload_field.field_def.offset.bytes)
    else:
        protocol = _field(packet, "next_header").value
        fragment_offset = 0
        more_fragments = False
        identification = None
        payload_field = transport_segment
        payload_start = offset + transport_segment.field_def.offset.bytes
    return _raw_fragment(capture, sequence, timestamps, packet, 6, protocol,
                         identification, fragment_offset, more_fragments,
                         payload_start, payload_field.field_def.size.bytes,
                         identification is not None)


def _raw_fragment(
    capture: bytearray,
    sequence: int,
    timestamps: dict[str, object],
    packet: object,
    ip_version: int,
    protocol: int,
    identification: int | None,
    fragment_offset: int,
    more_fragments: bool,
    payload_start: int,
    payload_length: int,
    is_fragmented: bool,
) -> _RawFragment:
    """Build a raw fragment backed by the original capture data."""
    source = bytes(_field(packet, "source_address").value)
    destination = bytes(_field(packet, "destination_address").value)
    if is_fragmented:
        key = (ip_version, source, destination, protocol, identification)
    else:
        key = (ip_version, sequence)
    payload = virtual_bytearray(
        (capture, ))[payload_start:payload_start + payload_length]
    return _RawFragment(sequence, timestamps, key, ip_version, source,
                        destination, protocol, identification, fragment_offset,
                        more_fragments, payload_start, payload)


def _reassemble(
    fragments: list[_RawFragment],
    progress_callback: Callable[[float], None] | None = None,
) -> list[ReassembledPacket]:
    """Reassemble raw IP fragments into complete packets."""
    groups: dict[tuple, list[_RawFragment]] = {}
    for fragment in fragments:
        groups.setdefault(fragment.key, []).append(fragment)

    packets = []
    for group_index, group in enumerate(groups.values()):
        group.sort(key=lambda fragment: (fragment.offset, fragment.sequence))
        expected_length = max(
            (fragment.offset + len(fragment.data)
             for fragment in group if not fragment.more_fragments),
            default=None)
        data_length = expected_length or max(
            fragment.offset + len(fragment.data) for fragment in group)
        chunks = []
        cursor = 0
        has_gap = False
        locations = []
        for fragment in group:
            fragment_end = min(data_length,
                               fragment.offset + len(fragment.data))
            length = fragment_end - fragment.offset
            locations.append(
                PacketFragment(fragment.sequence, fragment.timestamps,
                               fragment.capture_offset, fragment.offset, length,
                               fragment.more_fragments))
            if fragment.offset > cursor:
                chunks.append(bytes(fragment.offset - cursor))
                has_gap = True
                cursor = fragment.offset
            if fragment_end > cursor:
                chunk_start = cursor - fragment.offset
                chunks.append(fragment.data[chunk_start:length])
                cursor = fragment_end
        if cursor < data_length:
            chunks.append(bytes(data_length - cursor))
            has_gap = True
        data = virtual_bytearray(chunks)
        first = group[0]
        packets.append(
            ReassembledPacket(
                sequence=min(fragment.sequence for fragment in group),
                timestamps=first.timestamps,
                key=first.key,
                ip_version=first.ip_version,
                source_bytes=first.source,
                destination_bytes=first.destination,
                protocol=first.protocol,
                identification=first.identification,
                fragments=locations,
                data=data,
                complete=expected_length is not None and not has_gap,
            ))
        if progress_callback is not None:
            progress_callback((group_index + 1) / len(groups))
    packets.sort(key=lambda packet: packet.sequence)
    return packets
