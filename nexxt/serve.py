"""Foreground orchestration for multiple independent Nexxt camera sessions."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import threading
from collections.abc import Callable
from dataclasses import dataclass

from .config import ConfigFile, select_serve_cameras
from .device import CameraConfig, ClientConfig, DeviceConfig
from .media import MediaStream
from .rtsp import RtspServer

LOG = logging.getLogger("nexxt_lan")


@dataclass(frozen=True, slots=True)
class ServeCamera:
    name: str
    profile: DeviceConfig
    camera: CameraConfig
    path: str
    stream: MediaStream


def build_serve_cameras(
    config: ConfigFile,
    selectors: tuple[str, ...] | list[str],
    resolve_camera: Callable[[DeviceConfig], CameraConfig],
) -> tuple[ServeCamera, ...]:
    """Resolve selected profiles and validate their independent paths."""
    result: list[ServeCamera] = []
    seen: set[str] = set()
    for profile in select_serve_cameras(config, selectors):
        assert profile.rtsp_path is not None
        try:
            path = RtspServer.normalize_path(profile.rtsp_path)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"camera {profile.name!r} has invalid rtsp_path: {exc}"
            ) from exc
        if path in seen:
            raise RuntimeError(f"duplicate RTSP publication path {path}")
        seen.add(path)
        result.append(
            ServeCamera(
                profile.name, profile, resolve_camera(profile), path, MediaStream()
            )
        )
    return tuple(result)


async def run_serve(
    *,
    client: ClientConfig,
    cameras: tuple[ServeCamera, ...],
    listen: tuple[str, int],
    run_session: Callable[
        [ClientConfig, CameraConfig, MediaStream, threading.Event], None
    ],
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Run one RTSP listener while camera sessions execute independently.

    A failed session is reported and its stream ends, but the listener and
    every other session continue until an explicit process shutdown.
    """
    server = RtspServer(*listen)
    stop_sessions = threading.Event()
    shutdown = shutdown_event or asyncio.Event()
    loop = asyncio.get_running_loop()
    installed_signals: list[signal.Signals] = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown.set)
            installed_signals.append(sig)
        except (NotImplementedError, RuntimeError):
            # Windows and test worker threads do not support loop handlers;
            # KeyboardInterrupt at the CLI boundary still performs cleanup.
            pass

    async def camera_task(spec: ServeCamera) -> None:
        try:
            await asyncio.to_thread(
                run_session, client, spec.camera, spec.stream, stop_sessions
            )
        except Exception:
            LOG.exception("[error] camera %s session failed", spec.name)

    tasks: list[asyncio.Task[None]] = []
    try:
        await server.start()
        LOG.info("RTSP server listening on %s:%d", server.host, server.port)
        for spec in cameras:
            url = await server.publish(spec.path, spec.stream)
            LOG.info("%-10s -> %s", spec.name, url)
        tasks = [
            asyncio.create_task(camera_task(spec), name=f"nexxt-camera:{spec.name}")
            for spec in cameras
        ]
        await shutdown.wait()
    finally:
        stop_sessions.set()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for spec in cameras:
            spec.stream.close()
        for path in tuple(server.publications):
            with contextlib.suppress(KeyError):
                await server.unpublish(path)
        await server.stop()
        for sig in installed_signals:
            loop.remove_signal_handler(sig)
