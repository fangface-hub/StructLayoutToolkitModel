"""Tests for GUI-independent Lua StructInstance plugins."""
from types import SimpleNamespace

import pytest

from sltmodel.lua_plugins import LuaPluginError, LuaPluginManager


class _FieldInstance:
    def __init__(self, name, value):
        self.field_def = SimpleNamespace(name=name)
        self.value = value

    def with_value(self, value):
        return _FieldInstance(self.field_def.name, value)


class _StructInstance:
    def __init__(self, *field_instances, display_value=None):
        self.field_instances = list(field_instances)
        self.display_value = display_value

    def get_field(self, field_name):
        return next(
            (field for field in self.field_instances
             if field.field_def.name == field_name),
            None,
        )


def test_missing_plugin_directory_is_a_noop(tmp_path):
    """A missing plugin folder does not alter an instance."""
    instance = object()
    manager = LuaPluginManager(tmp_path / "plugins")

    assert manager.apply_decode(instance) is instance
    assert manager.apply_encode(instance) is instance


def test_decode_and_encode_hooks_transform_independent_instances(tmp_path):
    """Decode hooks mutate the decoded value; encode hooks receive a copy."""
    (tmp_path / "display.lua").write_text(
        """return {
  decode = function(instance)
    instance.display_value = "decoded"
    return instance
  end,
  encode = function(instance)
    instance.display_value = "encoded"
    return instance
  end,
}
""",
        encoding="utf-8",
    )
    instance = SimpleNamespace(field_instances=[], display_value=None)
    manager = LuaPluginManager(tmp_path)

    decoded = manager.apply_decode(instance)
    encoded = manager.apply_encode(decoded)

    assert decoded is instance
    assert decoded.display_value == "decoded"
    assert encoded is not decoded
    assert encoded.display_value == "encoded"
    assert decoded.display_value == "decoded"


def test_hooks_transform_primitive_and_nested_fields(tmp_path):
    (tmp_path / "nested.lua").write_text(
        """return {
  decode = function(instance)
    assert(instance.display_value == nil)
    assert(#instance.field_instances == 3)
    assert(instance:get_field("missing") == nil)
    assert(instance:get_field("number").value == 7)
    instance.display_value = "root"

    local number_field = instance:get_field("number")
    number_field.value = 42
    instance.field_instances[0] = number_field:with_value(43)
    local nested_field = instance:get_field("nested")
    local nested = nested_field.value
    nested.display_value = "nested display"
    nested.field_instances[0].value = "changed"
    assert(nested_field.value == nested)
    local nested_replacement = nested_field:with_value(nested)
    instance.field_instances[1] = nested_field
    instance.field_instances[2] = instance.field_instances[2]._field_instance
  end,
}
""",
        encoding="utf-8",
    )
    nested = _StructInstance(_FieldInstance("text", "original"))
    instance = _StructInstance(
        _FieldInstance("number", 7),
        _FieldInstance("nested", nested),
        _FieldInstance("unchanged", "value"),
    )

    result = LuaPluginManager(tmp_path).apply_decode(instance)

    assert result is instance
    assert result.display_value == "root"
    assert result.field_instances[0].value == 43
    assert result.field_instances[1].value is nested
    assert result.field_instances[2].value == "value"
    assert nested.display_value == "nested display"
    assert nested.field_instances[0].value == "changed"


def test_hooks_can_return_nil_or_replace_the_instance(tmp_path):
    (tmp_path / "a_nil.lua").write_text(
        """return { decode = function(instance)
  instance.display_value = "mutated"
end }
""",
        encoding="utf-8",
    )
    (tmp_path / "b_replace.lua").write_text(
        """return { decode = function(instance)
  assert(instance.display_value == "mutated")
  return "replacement"
end }
""",
        encoding="utf-8",
    )
    instance = _StructInstance()

    result = LuaPluginManager(tmp_path).apply_decode(instance)

    assert result == "replacement"
    assert instance.display_value == "mutated"


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("return nil", "must return a table"),
        ("return {", "Could not load plugin"),
    ],
)
def test_invalid_plugins_raise_a_named_error(tmp_path, source, message):
    (tmp_path / "broken.lua").write_text(source, encoding="utf-8")

    with pytest.raises(LuaPluginError, match=message):
        LuaPluginManager(tmp_path).apply_decode(_StructInstance())


def test_hook_errors_are_reported_with_plugin_and_hook_names(tmp_path):
    (tmp_path / "failure.lua").write_text(
        """return { encode = function(instance)
  error("cannot encode")
end }
""",
        encoding="utf-8",
    )

    with pytest.raises(
        LuaPluginError,
        match="Plugin 'failure.lua' encode hook failed:.*cannot encode",
    ):
        LuaPluginManager(tmp_path).apply_encode(_StructInstance())


def test_non_lua_files_and_plugins_without_hooks_are_ignored(tmp_path):
    (tmp_path / "notes.txt").write_text("not Lua", encoding="utf-8")
    (tmp_path / "no_hooks.lua").write_text("return {}", encoding="utf-8")
    instance = _StructInstance()
    manager = LuaPluginManager(tmp_path)

    assert manager.apply_decode(instance) is instance
    assert manager.apply_encode(instance) is instance
