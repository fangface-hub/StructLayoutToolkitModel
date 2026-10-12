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
conversion helpers, bundled PCAP/PCAPNG/PE/ELF layouts, and Lua plugin hooks.
It does not import or depend on Tkinter.

### Built-in layouts

```python
from sltmodel.resources import (load_elf_layout, load_pcap_layout,
                                load_pcapng_layout, load_pe_layout)

pe_layout = load_pe_layout()
elf_layout = load_elf_layout()
```

### Lua plugins

`LuaPluginManager` loads `*.lua` files from a caller-supplied directory and
applies their optional `decode(instance)` and `encode(instance)` hooks to
`StructInstance` values. The manager has no GUI dependency; it requires Lupa
when Lua plugins are loaded.

```python
from sltmodel.lua_plugins import LuaPluginManager

plugins = LuaPluginManager(plugin_directory)
display_instance = plugins.apply_decode(decoded_instance)
encoded_instance = plugins.apply_encode(display_instance)
```

## Development

```console
uv sync
uv run pytest -q
uv run pytest --cov=sltmodel --cov-branch --cov-report=term-missing -q
uv build
```

Generate a browsable HTML coverage report in `htmlcov/`:

```console
uv run pytest --cov=sltmodel --cov-branch --cov-report=html -q
```

Open `htmlcov/index.html` to inspect uncovered lines and branches.

To bump the package version, run one of these scripts from the repository root.
Each script resolves `pyproject.toml` and `uv.lock` relative to its own location.

```powershell
.\bump_major.ps1
.\bump_minor.ps1
.\bump_patch.ps1
```

The scripts update the `sltmodel` version in both `pyproject.toml` and `uv.lock`.
