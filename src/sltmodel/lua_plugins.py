"""Lua plugins that transform decoded and encodable struct instances."""
from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from importlib import import_module
from pathlib import Path


class LuaPluginError(ValueError):
    """Raised when a Lua plugin cannot be loaded or run."""


class _LuaStructInstance:
    """Expose a StructInstance to Lua without its item-access collision."""

    def __init__(
        self,
        instance: object,
        runtime: object,
        table_factory: Callable,
    ) -> None:
        self.instance = instance
        self._runtime = runtime
        self._table_factory = table_factory
        self._field_instances = instance.field_instances
        field_instances = runtime.table()
        for index, field_instance in enumerate(self._field_instances):
            field_instances[index] = _LuaFieldInstance(
                field_instance,
                runtime,
                table_factory,
            )
        self.field_instances = table_factory(
            field_instances,
            len(self._field_instances),
        )

    @property
    def display_value(self) -> object:
        """Return the plugin-defined value shown for this struct."""
        return getattr(self.instance, "display_value", None)

    @display_value.setter
    def display_value(self, value: object) -> None:
        """Store the plugin-defined value shown for this struct."""
        self.instance.display_value = value

    def get_field(self, field_name: str) -> object:
        """Return the first matching field instance."""
        field_instance = self.instance.get_field(field_name)
        if field_instance is None:
            return None
        return _LuaFieldInstance(
            field_instance,
            self._runtime,
            self._table_factory,
        )

    def sync_field_instances(self) -> None:
        """Apply Lua table item replacements to the original Python list."""
        for index, _ in enumerate(self._field_instances):
            field_instance = self.field_instances[index]
            if isinstance(field_instance, _LuaFieldInstance):
                field_instance = field_instance.to_field_instance()
            self._field_instances[index] = field_instance


class _LuaFieldInstance:
    """Expose immutable field values and nested StructInstances to Lua."""

    def __init__(
        self,
        field_instance: object,
        runtime: object,
        table_factory: Callable,
    ) -> None:
        self._field_instance = field_instance
        self._runtime = runtime
        self._table_factory = table_factory
        self.field_def = field_instance.field_def
        self._nested_instance: _LuaStructInstance | None = None
        self.is_struct = hasattr(field_instance.value, "field_instances")

    @property
    def value(self) -> object:
        """Return a Lua-safe nested structure or the primitive field value."""
        value = self._field_instance.value
        if hasattr(value, "field_instances"):
            if self._nested_instance is None:
                self._nested_instance = _LuaStructInstance(
                    value,
                    self._runtime,
                    self._table_factory,
                )
            return self._nested_instance
        return value

    @value.setter
    def value(self, value: object) -> None:
        """Replace the immutable field value through its public API."""
        self._field_instance = self._field_instance.with_value(value)
        self._nested_instance = None

    def with_value(self, value: object) -> "_LuaFieldInstance":
        """Return a Lua-safe replacement field instance."""
        if isinstance(value, _LuaStructInstance):
            value.sync_field_instances()
            value = value.instance
        return _LuaFieldInstance(
            self._field_instance.with_value(value),
            self._runtime,
            self._table_factory,
        )

    def to_field_instance(self) -> object:
        """Synchronize nested values and return the original field type."""
        if self._nested_instance is not None:
            self._nested_instance.sync_field_instances()
        return self._field_instance


class LuaPluginManager:
    """Load and apply Lua struct-instance transformation hooks."""

    def __init__(self, plugins_dir: Path | None) -> None:
        self._plugins_dir = plugins_dir
        self._hooks: dict[
            str,
            list[tuple[Path, Callable, object, Callable]],
        ] = {
            "decode": [],
            "encode": [],
        }
        self._loaded = False

    def apply_decode(self, instance: object) -> object:
        """Apply decode hooks after the codec creates a StructInstance."""
        return self._apply("decode", instance)

    def apply_encode(self, instance: object) -> object:
        """Apply encode hooks to a copy before codec serialization."""
        self._load()
        if not self._hooks["encode"]:
            return instance
        return self._apply("encode", deepcopy(instance))

    def _apply(self, hook_name: str, instance: object) -> object:
        self._load()
        transformed_instance = instance
        for plugin_path, hook, runtime, table_factory in self._hooks[hook_name]:
            lua_instance = _LuaStructInstance(
                transformed_instance,
                runtime,
                table_factory,
            )
            try:
                result = hook(lua_instance)
            except Exception as exc:  # Lupa maps Lua errors to Python errors.
                raise LuaPluginError(
                    f"Plugin '{plugin_path.name}' {hook_name} hook failed: "
                    f"{exc}") from exc
            lua_instance.sync_field_instances()
            if result is not None:
                if isinstance(result, _LuaStructInstance):
                    transformed_instance = result.instance
                else:
                    transformed_instance = result
        return transformed_instance

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self._plugins_dir is None or not self._plugins_dir.is_dir():
            return

        for plugin_path in sorted(self._plugins_dir.glob("*.lua")):
            try:
                runtime_class = getattr(import_module("lupa"), "LuaRuntime")
                runtime = runtime_class(unpack_returned_tuples=True)
                table_factory = runtime.eval(
                    "function(items, length) "
                    "return setmetatable(items, "
                    "{__len = function() return length end}) "
                    "end")
                plugin_source = plugin_path.read_text(encoding="utf-8")
                plugin = runtime.execute(plugin_source)
                if plugin is None:
                    raise LuaPluginError(
                        "Plugin must return a table containing hooks.")
                for hook_name, hooks in self._hooks.items():
                    hook = plugin[hook_name]
                    if hook is not None:
                        hooks.append(
                            (plugin_path, hook, runtime, table_factory))
            except Exception as exc:  # Lupa maps Lua errors to Python errors.
                if isinstance(exc, LuaPluginError):
                    raise
                raise LuaPluginError(
                    f"Could not load plugin '{plugin_path.name}': {exc}"
                ) from exc


NO_LUA_PLUGINS = LuaPluginManager(None)
