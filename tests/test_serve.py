import asyncio
import json
import threading

import pytest

import nexxt_lan
import nexxt.serve as serve_module
from nexxt.config import load_config
from nexxt.device import CameraConfig, ClientConfig
from nexxt.serve import build_serve_cameras, run_serve


def write_config(tmp_path, cameras):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "client": {
                    "uid_env": "UID",
                    "local_ip_env": "IP",
                    "stun_port_env": "STUN",
                },
                "cameras": cameras,
            }
        ),
        encoding="utf-8",
    )
    return path


def profile(name, *, path=None, rtsp=False, enabled=True):
    result = {
        "id": f"id-{name}",
        "name": name,
        "lan_protocol": "3.3",
        "signaling_port": 6668,
        "enabled": enabled,
        "ip_env": f"{name}_IP",
        "local_key_env": f"{name}_KEY",
        "password_env": f"{name}_PASSWORD",
    }
    if path is not None:
        result["rtsp_path"] = path
    if rtsp:
        result["rtsp"] = True
    return result


def fake_camera(profile):
    return CameraConfig(profile.name, profile.id, "192.0.2.1", 6668, "key", "pw")


def test_config_builds_multiple_independent_camera_streams_and_default_path(tmp_path):
    config = load_config(
        write_config(
            tmp_path,
            [profile("laundry", path="wash"), profile("cat-feeder", rtsp=True)],
        )
    )

    cameras = build_serve_cameras(config, [], fake_camera)

    assert [(item.name, item.path) for item in cameras] == [
        ("laundry", "/wash"),
        ("cat-feeder", "/cat-feeder"),
    ]
    assert cameras[0].stream is not cameras[1].stream


def test_serve_filter_only_allows_rtsp_enabled_profiles(tmp_path):
    config = load_config(
        write_config(tmp_path, [profile("laundry", path="laundry"), profile("private")])
    )
    assert [
        item.name for item in build_serve_cameras(config, ["laundry"], fake_camera)
    ] == ["laundry"]
    with pytest.raises(RuntimeError, match="not enabled for serve"):
        build_serve_cameras(config, ["private"], fake_camera)


def test_serve_filter_supports_multiple_cameras_and_rejects_disabled_profile(tmp_path):
    config = load_config(
        write_config(
            tmp_path,
            [
                profile("laundry", path="laundry"),
                profile("cat-feeder", path="cat-feeder"),
                profile("offline", path="offline", enabled=False),
            ],
        )
    )
    cameras = build_serve_cameras(config, ["cat-feeder", "laundry"], fake_camera)
    assert [camera.name for camera in cameras] == ["cat-feeder", "laundry"]
    with pytest.raises(RuntimeError, match="camera 'offline' is disabled"):
        build_serve_cameras(config, ["offline"], fake_camera)


def test_serve_without_filter_requires_an_rtsp_enabled_profile(tmp_path):
    config = load_config(
        write_config(tmp_path, [profile("private"), profile("also-private")])
    )
    with pytest.raises(RuntimeError, match="no RTSP-enabled cameras selected"):
        build_serve_cameras(config, [], fake_camera)


def test_duplicate_publication_paths_are_rejected_before_listener_starts(tmp_path):
    config = load_config(
        write_config(
            tmp_path, [profile("one", path="same"), profile("two", path="same")]
        )
    )
    with pytest.raises(RuntimeError, match="duplicate RTSP publication path /same"):
        build_serve_cameras(config, [], fake_camera)


def test_invalid_publication_path_is_rejected_before_listener_starts(tmp_path):
    config = load_config(write_config(tmp_path, [profile("one", path="not/a-path")]))
    with pytest.raises(RuntimeError, match="camera 'one' has invalid rtsp_path"):
        build_serve_cameras(config, [], fake_camera)


def test_serve_cli_keeps_legacy_cli_and_supports_repeatable_camera_filter():
    legacy = nexxt_lan.parse_args(["--config", "x.json", "--camera", "one"])
    serve = nexxt_lan.parse_args(
        [
            "serve",
            "--config",
            "x.json",
            "--camera",
            "one",
            "--camera",
            "two",
            "--rtsp-listen",
            "127.0.0.1:8554",
        ]
    )
    assert legacy.command == "preview"
    assert serve.command == "serve"
    assert serve.camera == ["one", "two"]


def test_serve_cli_help_explains_unfiltered_selection(capsys):
    with pytest.raises(SystemExit) as exc_info:
        nexxt_lan.parse_args(["serve", "--help"])
    assert exc_info.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "If omitted, publish all RTSP-enabled cameras." in help_text


def test_run_serve_uses_one_listener_and_failure_does_not_stop_other_camera(
    tmp_path, monkeypatch
):
    config = load_config(
        write_config(
            tmp_path,
            [profile("broken", path="broken"), profile("healthy", path="healthy")],
        )
    )
    cameras = build_serve_cameras(config, [], fake_camera)
    shutdown = asyncio.Event()
    started = []
    healthy_stopped = threading.Event()
    created = []

    class RecordingServer(serve_module.RtspServer):
        async def publish(self, path, stream):
            created.append(self)
            return await super().publish(path, stream)

    monkeypatch.setattr(serve_module, "RtspServer", RecordingServer)

    def runner(_client, camera, stream, stop_event):
        started.append((camera.name, stream))
        if camera.name == "broken":
            raise RuntimeError("synthetic failure")
        while not stop_event.wait(0.01):
            pass
        healthy_stopped.set()

    async def exercise():
        task = asyncio.create_task(
            run_serve(
                client=None,  # runner deliberately does not need a real client
                cameras=cameras,
                listen=("127.0.0.1", 0),
                run_session=runner,
                shutdown_event=shutdown,
            )
        )
        for _ in range(100):
            if len(started) == 2:
                break
            await asyncio.sleep(0.01)
        assert {name for name, _stream in started} == {"broken", "healthy"}
        # The successful stream is still open while its sibling has failed.
        assert cameras[1].stream._closed is False
        shutdown.set()
        await task

    asyncio.run(exercise())
    assert len({id(server) for server in created}) == 1
    assert len(created) == 2
    assert healthy_stopped.is_set()
    assert all(camera.stream._closed for camera in cameras)


def test_serve_mocked_sessions_reserve_independent_stun_endpoints(tmp_path):
    config = load_config(
        write_config(
            tmp_path,
            [
                profile("laundry", path="laundry"),
                profile("cat-feeder", path="cat-feeder"),
            ],
        )
    )
    cameras = build_serve_cameras(config, [], fake_camera)
    client = ClientConfig("client", "127.0.0.1", 3478)
    shutdown = asyncio.Event()
    endpoints = []
    started = threading.Event()

    def runner(shared_client, camera, _stream, stop_event):
        endpoint, endpoint_client = nexxt_lan.open_local_stun_endpoint(
            shared_client, port=0
        )
        try:
            endpoint.start(f"password-{camera.name}")
            endpoints.append((camera.name, endpoint, endpoint_client))
            if len(endpoints) == 2:
                started.set()
            stop_event.wait(1)
        finally:
            endpoint.close()

    async def exercise():
        task = asyncio.create_task(
            run_serve(
                client=client,
                cameras=cameras,
                listen=("127.0.0.1", 0),
                run_session=runner,
                shutdown_event=shutdown,
            )
        )
        while not started.is_set():
            await asyncio.sleep(0.01)
        assert {item[2].stun_port for item in endpoints} == {
            item[1].port for item in endpoints
        }
        assert endpoints[0][1].port != endpoints[1][1].port
        shutdown.set()
        await task

    asyncio.run(exercise())
