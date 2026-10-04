"""Pure struct-instance/model helpers (no Tkinter dependencies).

These operate only on StructInstance/FieldInstance/StructDef data and are
shared by BinaryEditorWindow's tree-building and value-editing code.
"""
from __future__ import annotations

from ast import literal_eval
from dataclasses import replace

from sltcodec import StructDef, TypeDict
from sltcore import InfoSize


def minimum_struct_size(struct_def: StructDef) -> int:
    """Return the minimum byte length required by static field layouts."""
    minimum_size = InfoSize()
    for field_def in struct_def.fields:
        if not isinstance(field_def.offset, InfoSize):
            raise ValueError(
                f"Field '{field_def.name}' has an offset expression.")
        if not isinstance(field_def.size, InfoSize):
            raise ValueError(f"Field '{field_def.name}' has a size expression.")
        if isinstance(field_def.repeat, str):
            raise ValueError(
                f"Field '{field_def.name}' has a repeat expression.")

        repeat = (field_def.repeat
                  if field_def.repeat and field_def.repeat > 1 else 1)
        field_end = field_def.offset + repeat * field_def.size
        if field_end > minimum_size:
            minimum_size = field_end
    return minimum_size.bytes


def field_instance_at_path(instance: object, field_path: tuple[int,
                                                               ...]) -> object:
    """Return the field instance addressed by a nested field path."""
    field_instance = None
    for field_index in field_path:
        field_instance = instance.field_instances[field_index]
        instance = field_instance.value
    return field_instance


def replace_instance_field_value(
    instance: object,
    field_path: tuple[int, ...],
    value: object,
    type_dict: TypeDict,
) -> object:
    """Replace the value at a nested field path with an explicit value."""
    field_index = field_path[0]
    field_instances = list(instance.field_instances)
    field_instance = field_instances[field_index]
    if len(field_path) == 1:
        updated_field_instance = field_instance.with_value(value, type_dict)
    else:
        nested_value = replace_instance_field_value(
            field_instance.value,
            field_path[1:],
            value,
            type_dict,
        )
        updated_field_instance = field_instance.with_value(
            nested_value,
            type_dict,
        )
    field_instances[field_index] = updated_field_instance
    return replace(instance, field_instances=field_instances)


def replace_instance_value(
    instance: object,
    field_path: tuple[int, ...],
    text: str,
    type_dict: TypeDict,
) -> object:
    """Replace the value at a nested field path, parsing text for the leaf."""
    field_index = field_path[0]
    field_instances = list(instance.field_instances)
    field_instance = field_instances[field_index]
    if len(field_path) == 1:
        value = parse_field_value(text, field_instance, type_dict)
        updated_field_instance = field_instance.with_value(value, type_dict)
    else:
        value = replace_instance_value(
            field_instance.value,
            field_path[1:],
            text,
            type_dict,
        )
        updated_field_instance = field_instance.with_value(value, type_dict)
    field_instances[field_index] = updated_field_instance
    return replace(instance, field_instances=field_instances)


def parse_field_value(
    text: str,
    field_instance: object,
    type_dict: TypeDict,
) -> object:
    """Parse a field value, accepting enum names when one is configured."""
    enum_values = _enum_values(getattr(field_instance, "field_def", None),
                               type_dict)
    stripped = text.strip()
    if enum_values is not None:
        if stripped in enum_values:
            return enum_values[stripped]
        for name, value in enum_values.items():
            if stripped == f"{name} ({format_value(value)})":
                return value
    return parse_value(text, field_instance.value)


def parse_value(text: str, current_value: object) -> object:
    """Parse edited cell text into a value matching current_value's type."""
    if hasattr(current_value, "field_instances") and hasattr(
            current_value, "display_value"):
        current_value.display_value = text
        return current_value
    if isinstance(current_value, bool):
        values = {"true": True, "false": False, "1": True, "0": False}
        try:
            return values[text.strip().lower()]
        except KeyError as exc:
            raise ValueError("Boolean value must be true or false.") from exc
    if isinstance(current_value, int):
        try:
            return int(text, 0)
        except ValueError:
            return int(text, 10)
    if isinstance(current_value, float):
        return float(text)
    if isinstance(current_value, bytes):
        return bytes.fromhex(text)
    if isinstance(current_value, bytearray):
        return bytearray.fromhex(text)
    if isinstance(current_value, str):
        return text
    parsed = literal_eval(text)
    if not isinstance(parsed, type(current_value)):
        raise ValueError(f"Value must be {type(current_value).__name__}.")
    return parsed


def format_type(field_type: object) -> str:
    """Format a field's type for display."""
    if isinstance(field_type, StructDef):
        return field_type.name or "StructDef"
    return str(field_type)


def format_value(value: object) -> str:
    """Format a field's value for display."""
    if hasattr(value, "field_instances"):
        return str(getattr(value, "display_value", "<StructInstance>"))
    if isinstance(value, (bytes, bytearray)):
        return value.hex(" ").upper()
    return str(value)


def format_field_value(field_instance: object, type_dict: TypeDict) -> str:
    """Format a field value with its enum name when available."""
    value_text = format_value(field_instance.value)
    enum_values = _enum_values(getattr(field_instance, "field_def", None),
                               type_dict)
    if enum_values is None:
        return value_text
    for name, value in enum_values.items():
        if value == field_instance.value:
            return f"{name} ({value_text})"
    return value_text


def _enum_values(
    field_def: object,
    type_dict: TypeDict,
) -> dict[str, int] | None:
    """Return the configured enum values for a field, if any."""
    enum_def_name = getattr(field_def, "enum_def_name", None)
    if not enum_def_name:
        return None
    enum_def = type_dict.enum_dict.get(enum_def_name)
    return enum_def.values if enum_def is not None else None
