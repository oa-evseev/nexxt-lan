import asyncio
import importlib
import sys
import types
from enum import Enum, IntFlag

import pytest


@pytest.fixture
def ha_modules(monkeypatch):
    """Install the small HA API surface used by this adapter.

    The repository's normal test environment deliberately does not install
    Home Assistant. These contract fakes keep the adapter tests focused while
    Home Assistant supplies the real classes when the integration is loaded.
    """
    homeassistant = types.ModuleType("homeassistant")
    homeassistant.__path__ = []

    config_entries = types.ModuleType("homeassistant.config_entries")

    class ConfigFlow:
        def __init_subclass__(cls, **kwargs):
            cls.domain = kwargs.pop("domain", None)
            super().__init_subclass__(**kwargs)

        async def async_set_unique_id(self, unique_id):
            self.unique_id = unique_id

        def _abort_if_unique_id_configured(self):
            return None

        def async_create_entry(self, **kwargs):
            return {"type": "create_entry", **kwargs}

        def async_show_form(self, **kwargs):
            return {"type": "form", **kwargs}

    class ConfigEntry:
        def __init__(self, data, entry_id="entry-1"):
            self.data = data
            self.entry_id = entry_id
            self.runtime_data = None
            self.unload_callbacks = []

        def async_on_unload(self, callback):
            self.unload_callbacks.append(callback)

        def add_update_listener(self, callback):
            self.update_listener = callback
            return lambda: None

    config_entries.ConfigFlow = ConfigFlow
    config_entries.ConfigEntry = ConfigEntry
    config_entries.ConfigFlowResult = dict
    homeassistant.config_entries = config_entries

    const = types.ModuleType("homeassistant.const")

    class Platform(Enum):
        CAMERA = "camera"

    const.Platform = Platform
    const.EVENT_HOMEASSISTANT_STOP = "homeassistant_stop"

    core = types.ModuleType("homeassistant.core")
    core.Event = type("Event", (), {})
    core.HomeAssistant = type("HomeAssistant", (), {})

    exceptions = types.ModuleType("homeassistant.exceptions")
    exceptions.ConfigEntryNotReady = type("ConfigEntryNotReady", (Exception,), {})

    camera_module = types.ModuleType("homeassistant.components.camera")

    class CameraEntityFeature(IntFlag):
        STREAM = 2

    class Camera:
        def __init__(self):
            pass

    camera_module.Camera = Camera
    camera_module.CameraEntityFeature = CameraEntityFeature

    device_registry = types.ModuleType("homeassistant.helpers.device_registry")

    class DeviceInfo(dict):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)

    device_registry.DeviceInfo = DeviceInfo
    entity_platform = types.ModuleType("homeassistant.helpers.entity_platform")
    entity_platform.AddEntitiesCallback = object

    voluptuous = types.ModuleType("voluptuous")

    class Required:
        def __init__(self, key, default=None):
            self.key = key
            self.default = default

    class Schema:
        def __init__(self, schema):
            self.schema = schema

    voluptuous.Required = Required
    voluptuous.Schema = Schema

    modules = {
        "homeassistant": homeassistant,
        "homeassistant.config_entries": config_entries,
        "homeassistant.const": const,
        "homeassistant.core": core,
        "homeassistant.exceptions": exceptions,
        "homeassistant.components": types.ModuleType("homeassistant.components"),
        "homeassistant.components.camera": camera_module,
        "homeassistant.helpers": types.ModuleType("homeassistant.helpers"),
        "homeassistant.helpers.device_registry": device_registry,
        "homeassistant.helpers.entity_platform": entity_platform,
        "voluptuous": voluptuous,
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    for name in list(sys.modules):
        if name.startswith("custom_components.nexxt_lan"):
            monkeypatch.delitem(sys.modules, name)
    return config_entries, CameraEntityFeature


class FakeHass:
    def __init__(self):
        self.config_entries = FakeConfigEntries()
        self.bus = FakeBus()

    async def async_add_executor_job(self, target, *args):
        return target(*args)


class FakeConfigEntries:
    def __init__(self):
        self.forwarded = []
        self.unloaded = []
        self.reloaded = []

    async def async_forward_entry_setups(self, entry, platforms):
        self.forwarded.append((entry, platforms))

    async def async_unload_platforms(self, entry, platforms):
        self.unloaded.append((entry, platforms))
        return True

    async def async_reload(self, entry_id):
        self.reloaded.append(entry_id)


class FakeBus:
    def async_listen_once(self, event, callback):
        self.event = event
        self.callback = callback
        return lambda: None


def test_config_flow_validates_path_and_rejects_invalid_config(
    ha_modules, tmp_path, monkeypatch
):
    flow_module = importlib.import_module("custom_components.nexxt_lan.config_flow")
    valid = tmp_path / "nexxt.json"
    valid.write_text("{}", encoding="utf-8")
    validated = []

    def validate(path):
        validated.append(path)

    monkeypatch.setattr(flow_module, "validate_config_file", validate)
    flow = flow_module.NexxtLanConfigFlow()
    flow.hass = FakeHass()
    result = asyncio.run(flow.async_step_user({"config_path": str(valid)}))
    assert result["type"] == "create_entry"
    assert result["title"] == "Nexxt LAN"
    assert result["data"] == {"config_path": str(valid.resolve())}
    assert validated == [valid]

    def reject(_path):
        raise RuntimeError("invalid")

    monkeypatch.setattr(flow_module, "validate_config_file", reject)
    rejected = flow_module.NexxtLanConfigFlow()
    rejected.hass = FakeHass()
    result = asyncio.run(rejected.async_step_user({"config_path": str(valid)}))
    assert result["type"] == "form"
    assert result["errors"] == {"base": "invalid_config"}


def test_setup_unload_and_shutdown_share_one_manager(ha_modules, monkeypatch):
    config_entries, _feature = ha_modules
    integration = importlib.import_module("custom_components.nexxt_lan")

    class Manager:
        def __init__(self):
            self.starts = 0
            self.stops = 0

        async def async_start(self):
            self.starts += 1

        async def async_stop(self):
            self.stops += 1

    manager = Manager()
    factory_calls = []

    class Factory:
        @classmethod
        def from_config_file(cls, path, **kwargs):
            factory_calls.append((path, kwargs))
            return manager

    monkeypatch.setattr(integration, "NexxtLanManager", Factory)
    entry = config_entries.ConfigEntry({"config_path": "/config/nexxt.json"})
    hass = FakeHass()

    assert asyncio.run(integration.async_setup_entry(hass, entry)) is True
    assert entry.runtime_data is manager
    assert manager.starts == 1
    assert len(factory_calls) == 1
    assert len(hass.config_entries.forwarded) == 1
    assert asyncio.run(integration.async_unload_entry(hass, entry)) is True
    assert manager.stops == 1
    assert len(hass.config_entries.unloaded) == 1


def test_camera_entities_use_device_ids_stream_urls_and_shared_manager(ha_modules):
    config_entries, feature = ha_modules
    camera_module = importlib.import_module("custom_components.nexxt_lan.camera")

    class CameraDescription:
        def __init__(self, device_id, name, path):
            self.device_id = device_id
            self.name = name
            self.rtsp_path = path

    cameras = [
        CameraDescription("dev-1", "Laundry", "/laundry"),
        CameraDescription("dev-2", "Nursery", "/nursery"),
    ]

    class Manager:
        def __init__(self):
            self.cameras = tuple(cameras)

        def stream_source(self, camera):
            return f"rtsp://127.0.0.1:8554{camera.rtsp_path}"

    manager = Manager()
    entry = config_entries.ConfigEntry({})
    entry.runtime_data = manager
    entities = []
    asyncio.run(
        camera_module.async_setup_entry(None, entry, lambda new: entities.extend(new))
    )

    assert len(entities) == 2
    assert all(entity._manager is manager for entity in entities)
    assert [entity._attr_unique_id for entity in entities] == ["dev-1", "dev-2"]
    assert [entity._attr_name for entity in entities] == ["Laundry", "Nursery"]
    assert all(entity._attr_supported_features == feature.STREAM for entity in entities)
    assert asyncio.run(entities[0].stream_source()) == ("rtsp://127.0.0.1:8554/laundry")
