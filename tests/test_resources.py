"""Tests for bundled StructLayout resources."""
from sltmodel.resources import load_elf_layout, load_pe_layout


def test_load_pe_layout():
    """The bundled PE layout exposes its root structure and enums."""
    layout = load_pe_layout()

    assert layout.struct_def_name == "pe_file"
    assert {"pe_dos_header", "pe_coff_header",
            "pe_section_header"} <= set(layout.type_dict.struct_dict)
    assert {"Machine", "OptionalHeaderMagic"} <= set(layout.type_dict.enum_dict)


def test_load_elf_layout():
    """The bundled ELF layout exposes its root structure and enums."""
    layout = load_elf_layout()

    assert layout.struct_def_name == "elf_file"
    assert {"elf_program_header_32",
            "elf_program_header_64"} <= set(layout.type_dict.struct_dict)
    assert {"Class", "DataEncoding", "Machine"} <= set(
        layout.type_dict.enum_dict)
