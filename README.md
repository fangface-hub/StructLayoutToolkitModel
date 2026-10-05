# StructLayoutToolkitModel

StructLayoutToolkitModel (distribution name `sltmodel`) is a standalone,
GUI-independent model library that handles StructLayout definitions and binary
decoding. It provides the structure engine used by StructLayoutToolkitGui and
is intended for reuse by other clients such as a CLI.

## Installation

```console
python -m pip install sltmodel
```

## API

```python
from sltmodel import CaptureDocument, PayloadStructDef
from sltmodel.resources import load_pcap_layout

capture = CaptureDocument.from_bytes(capture_bytes)
pcap_layout = load_pcap_layout()
```

The package provides capture parsing and IP fragment reassembly, conditional
payload StructLayout definitions, StructInstance value helpers, InfoSize
conversion helpers, and the bundled PCAP/PCAPNG layouts. It does not import or
depend on Tkinter.

## Development

```console
uv sync
uv run pytest -q
uv build
```

To bump the package version, run one of these scripts from the repository root.
Each script resolves `pyproject.toml` and `uv.lock` relative to its own location.

```powershell
.\bump_major.ps1
.\bump_minor.ps1
.\bump_patch.ps1
```

The scripts update the `sltmodel` version in both `pyproject.toml` and `uv.lock`.
