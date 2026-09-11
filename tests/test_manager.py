import asyncio
import json
import threading

import pytest

from nexxt import NexxtLanManager, validate_config_file


def write_config(tmp_path, cameras):
    path = tmp_path / "nexxt.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "client": {
                    "uid_env": "TEST_UID",
                    "local_ip_env": "TEST_LOCAL_IP",
                    "stun_port_env": "TEST_STUN_PORT",
                },
                "cameras": cameras,
            }
        ),
        encoding="utf-8",
    )
    return path


def profile(name, device_id, path):
    upper = name.upper().replace("-", "_")
    return {
        "id": device_id,
        "name": name,
        "lan_protocol": "3.3",
        "signaling_port": 6668,
        "enabled": True,
        "rtsp_path": path,
        "ip_env": f"{upper}_IP",
        "local_key_env": f"{upper}_KEY",
        "password_env": f"{upper}_PASSWORD",
    }


def set_runtime(monkeypatch, cameras):
    monkeypatch.setenv("TEST_UID", "client-id")
    monkeypatch.setenv("TEST_LOCAL_IP", "127.0.0.1")
    monkeypatch.setenv("TEST_STUN_PORT", "3478")
    for camera in cameras:
        upper = camera["name"].upper().replace("-", "_")
        monkeypatch.setenv(f"{upper}_IP", "192.0.2.10")
        monkeypatch.setenv(f"{upper}_KEY", "local-key")
        monkeypatch.setenv(f"{upper}_PASSWORD", "password")


def test_validation_does_not_require_runtime_environment(tmp_path):
    path = write_config(tmp_path, [profile("Laundry", "device-1", "laundry")])
    config = validate_config_file(path)
    assert config.cameras[0].name == "Laundry"


def test_validation_rejects_duplicate_stable_device_ids(tmp_path):
    path = write_config(
        tmp_path,
        [
            profile("Laundry", "same-device", "laundry"),
            profile("Nursery", "same-device", "nursery"),
        ],
    )
    with pytest.raises(RuntimeError, match="duplicate camera device id"):
        validate_config_file(path)


def test_manager_shares_server_isolates_failures_and_cleans_up(tmp_path, monkeypatch):
    profiles = [
        profile("Broken", "device-broken", "broken"),
        profile("Healthy", "device-healthy", "healthy"),
    ]
    path = write_config(tmp_path, profiles)
    set_runtime(monkeypatch, profiles)
    healthy_started = threading.Event()
    healthy_stopped = threading.Event()

    def run_session(_client, camera, _stream, stop_event):
        if camera.name == "Broken":
            raise RuntimeError("synthetic camera failure")
        healthy_started.set()
        stop_event.wait(2)
        healthy_stopped.set()

    async def exercise():
        manager = NexxtLanManager.from_config_file(
            path,
            listen=("127.0.0.1", 0),
            session_runner=run_session,
        )
        await manager.async_start()
        for _ in range(100):
            if healthy_started.is_set() and manager.session_errors:
                break
            await asyncio.sleep(0.01)

        assert [camera.name for camera in manager.cameras] == ["Broken", "Healthy"]
        assert [camera.device_id for camera in manager.cameras] == [
            "device-broken",
            "device-healthy",
        ]
        assert manager.server.running
        assert set(manager.server.publications) == {"/broken", "/healthy"}
        assert "device-broken" in manager.session_errors
        assert "device-healthy" not in manager.session_errors
        urls = [manager.stream_source(camera) for camera in manager.cameras]
        assert urls == [
            f"rtsp://127.0.0.1:{manager.server.port}/broken",
            f"rtsp://127.0.0.1:{manager.server.port}/healthy",
        ]
        await manager.async_stop()
        await manager.async_stop()
        assert not manager.server.running
        assert manager.server.publications == ()

    asyncio.run(exercise())
    assert healthy_stopped.is_set()
