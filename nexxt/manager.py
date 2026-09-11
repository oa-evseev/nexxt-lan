"""Public in-process lifecycle for multi-camera Nexxt LAN streaming."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import (
    ConfigFile,
    assemble_camera_config,
    load_config,
    resolve_client_config,
    resolve_device_credentials,
    resolve_device_runtime,
    resolve_rtc_mode,
)
from .device import CameraConfig, ClientConfig
from .media import MediaStream
from .rtsp import RtspServer
from .serve import ServeCamera, build_serve_cameras, validate_serve_config

LOG = logging.getLogger("nexxt_lan")

SessionRunner = Callable[
    [ClientConfig, CameraConfig, MediaStream, threading.Event], None
]


@dataclass(frozen=True, slots=True)
class ManagedCamera:
    """Stable camera metadata exposed to embedding applications."""

    device_id: str
    name: str
    rtsp_path: str


def validate_config_file(path: str | Path) -> ConfigFile:
    """Load and validate a config without resolving secrets or opening I/O."""
    config = load_config(Path(path).expanduser())
    validate_serve_config(config)
    return config


def _default_session_runner(
    client: ClientConfig,
    camera: CameraConfig,
    stream: MediaStream,
    stop_event: threading.Event,
) -> None:
    # The complete protocol implementation remains at its existing public
    # entry point. Import lazily so config validation has no protocol side
    # effects and to avoid an import cycle while nexxt_lan imports nexxt.
    from nexxt_lan import run_lan_preview

    run_lan_preview(
        client=client,
        camera=camera,
        debug=False,
        rtc_mode=resolve_rtc_mode(camera),
        media_sinks=[stream],
        stop_event=stop_event,
        configure_logging=False,
        local_stun_port=0,
    )


class NexxtLanManager:
    """Own one RTSP listener and all sessions for one loaded config.

    Camera session failures are isolated: an exception ends only that camera's
    worker while the shared listener and sibling sessions remain alive.
    """

    def __init__(
        self,
        config: ConfigFile,
        *,
        listen: tuple[str, int] = ("127.0.0.1", 8554),
        session_runner: SessionRunner | None = None,
        server_factory: Callable[[str, int], RtspServer] = RtspServer,
    ) -> None:
        validate_serve_config(config)
        self._client = resolve_client_config(config)
        self._specs = build_serve_cameras(
            config,
            (),
            lambda profile: assemble_camera_config(
                profile,
                resolve_device_runtime(profile),
                resolve_device_credentials(profile),
            ),
        )
        self._cameras = tuple(
            ManagedCamera(spec.profile.id, spec.name, spec.path) for spec in self._specs
        )
        self._server = server_factory(*listen)
        self._session_runner = session_runner or _default_session_runner
        self._stop_sessions = threading.Event()
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._session_errors: dict[str, Exception] = {}
        self._started = False
        self._stopped = False

    @classmethod
    def from_config_file(
        cls,
        path: str | Path,
        **kwargs: object,
    ) -> "NexxtLanManager":
        """Load an existing nexxt-lan config and create its manager."""
        return cls(load_config(Path(path).expanduser()), **kwargs)

    @property
    def cameras(self) -> tuple[ManagedCamera, ...]:
        return self._cameras

    @property
    def server(self) -> RtspServer:
        """The single RTSP server shared by every managed camera."""
        return self._server

    @property
    def session_errors(self) -> dict[str, Exception]:
        """A snapshot of camera worker failures, keyed by stable device ID."""
        return dict(self._session_errors)

    def stream_source(self, camera: ManagedCamera) -> str:
        """Return the camera publication URL on the shared listener."""
        if camera not in self._cameras:
            raise KeyError(camera.device_id)
        return self._server.url(camera.rtsp_path)

    async def _run_camera(self, camera: ManagedCamera, spec: ServeCamera) -> None:
        try:
            await asyncio.to_thread(
                self._session_runner,
                self._client,
                spec.camera,
                spec.stream,
                self._stop_sessions,
            )
        except Exception as exc:
            self._session_errors[camera.device_id] = exc
            LOG.exception("[error] camera %s session failed", camera.name)

    async def async_start(self) -> None:
        """Start the listener, publish all streams, then start all sessions."""
        if self._started:
            return
        if self._stopped:
            raise RuntimeError("NexxtLanManager cannot be restarted after stop")
        try:
            await self._server.start()
            for spec in self._specs:
                await self._server.publish(spec.path, spec.stream)
            self._tasks = {
                camera.device_id: asyncio.create_task(
                    self._run_camera(camera, spec),
                    name=f"nexxt-camera:{camera.device_id}",
                )
                for camera, spec in zip(self._cameras, self._specs, strict=True)
            }
            self._started = True
        except BaseException:
            await self._cleanup()
            raise

    async def _cleanup(self) -> None:
        self._stop_sessions.set()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
            self._tasks.clear()
        for spec in self._specs:
            spec.stream.close()
        await self._server.stop()

    async def async_stop(self) -> None:
        """Stop sessions and close all media and RTSP resources once."""
        if self._stopped:
            return
        self._stopped = True
        await self._cleanup()
        self._started = False
