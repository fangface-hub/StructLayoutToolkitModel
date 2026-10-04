"""GUI-independent data models and operations for StructLayoutToolkit."""
from importlib import import_module

_EXPORTS = {
    "format_infosize": (".infosize", "format_infosize"),
    "infosize_to_json_data": (".infosize", "infosize_to_json_data"),
    "infosize_value_to_string": (".infosize", "infosize_value_to_string"),
    "parse_infosize_input": (".infosize", "parse_infosize_input"),
    "CaptureDocument": (".packet_data", "CaptureDocument"),
    "PacketFragment": (".packet_data", "PacketFragment"),
    "ReassembledPacket": (".packet_data", "ReassembledPacket"),
    "internet_checksum": (".packet_data", "internet_checksum"),
    "PayloadStructDef": (".payload_struct_defs", "PayloadStructDef"),
    "load_payload_struct_defs": (".payload_struct_defs",
                                 "load_payload_struct_defs"),
    "matching_struct_layout": (".payload_struct_defs",
                               "matching_struct_layout"),
    "packet_eval_env": (".payload_struct_defs", "packet_eval_env"),
    "save_payload_struct_defs": (".payload_struct_defs",
                                 "save_payload_struct_defs"),
    "field_instance_at_path": (".struct_instance", "field_instance_at_path"),
    "format_field_value": (".struct_instance", "format_field_value"),
    "format_type": (".struct_instance", "format_type"),
    "format_value": (".struct_instance", "format_value"),
    "minimum_struct_size": (".struct_instance", "minimum_struct_size"),
    "parse_field_value": (".struct_instance", "parse_field_value"),
    "parse_value": (".struct_instance", "parse_value"),
    "replace_instance_field_value": (".struct_instance",
                                     "replace_instance_field_value"),
    "replace_instance_value": (".struct_instance", "replace_instance_value"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str):
    """Load model APIs only when requested."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}"
                             ) from exc
    return getattr(import_module(module_name, __name__), attribute_name)
