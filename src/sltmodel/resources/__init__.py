"""Bundled capture StructLayout resources."""
from importlib.resources import as_file, files

from sltcodec import StructLayout, load_struct_layout

__all__ = ["load_pcap_layout", "load_pcapng_layout"]


def _load_layout(filename: str) -> StructLayout:
    resource = files(__name__).joinpath(filename)
    with as_file(resource) as path:
        return load_struct_layout(path)


def load_pcap_layout() -> StructLayout:
    """Load the bundled PCAP StructLayout."""
    return _load_layout("pcap.json")


def load_pcapng_layout() -> StructLayout:
    """Load the bundled PCAPNG StructLayout."""
    return _load_layout("pcapng.json")
