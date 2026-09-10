"""A small multi-publication asyncio RTSP 1.0 server.

One listener can publish independent :class:`nexxt.media.MediaStream` objects
at distinct paths. The implementation intentionally covers the playback
subset used by ordinary RTSP clients: RTP over RTSP/TCP and unicast UDP.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import random
import re
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote, urlsplit

from .media import AudioChunk, MediaStream, MediaSubscription, VideoChunk

LOG = logging.getLogger("nexxt_lan")
MAX_CLIENT_WRITE_BUFFER = 2 * 1024 * 1024
_PUBLICATION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]*\Z")


def _rtp_header(
    payload_type: int, sequence: int, timestamp: int, ssrc: int, marker: bool
) -> bytes:
    return struct.pack(
        ">BBHII",
        0x80,
        payload_type | (0x80 if marker else 0),
        sequence,
        timestamp,
        ssrc,
    )


class _RtpTrack:
    """RTP state owned by one track of one RTSP client."""

    def __init__(self, payload_type: int, clock_rate: int) -> None:
        self.payload_type = payload_type
        self.clock_rate = clock_rate
        self.sequence = random.randrange(65536)
        self.ssrc = random.randrange(1, 2**32)
        self.base_ns: Optional[int] = None
        self.base_timestamp = random.randrange(2**32)
        self.audio_timestamp = self.base_timestamp

    def timestamp(self, timestamp_ns: int) -> int:
        if self.base_ns is None:
            self.base_ns = timestamp_ns
        return (
            self.base_timestamp
            + (timestamp_ns - self.base_ns) * self.clock_rate // 1_000_000_000
        ) & 0xFFFFFFFF

    def packet(self, payload: bytes, timestamp: int, marker: bool = False) -> bytes:
        result = (
            _rtp_header(self.payload_type, self.sequence, timestamp, self.ssrc, marker)
            + payload
        )
        self.sequence = (self.sequence + 1) & 0xFFFF
        return result

    def hevc(self, chunk: VideoChunk, mtu: int = 1200) -> list[bytes]:
        nal = chunk.payload
        if len(nal) < 2:
            return []
        timestamp = self.timestamp(chunk.timestamp_ns)
        marker = chunk.nal_type < 32
        if len(nal) <= mtu:
            return [self.packet(nal, timestamp, marker)]
        nal_type = (nal[0] >> 1) & 0x3F
        indicator = bytes(((nal[0] & 0x81) | (49 << 1), nal[1]))
        parts = [nal[pos : pos + mtu - 3] for pos in range(2, len(nal), mtu - 3)]
        packets = []
        for index, part in enumerate(parts):
            fu_header = (
                nal_type
                | (0x80 if index == 0 else 0)
                | (0x40 if index == len(parts) - 1 else 0)
            )
            packets.append(
                self.packet(
                    indicator + bytes((fu_header,)) + part,
                    timestamp,
                    marker and index == len(parts) - 1,
                )
            )
        return packets

    def pcm(self, chunk: AudioChunk, mtu: int = 1200) -> list[bytes]:
        # RTP L16 is network-byte-order. This is lossless repacketization,
        # not transcoding the camera's signed little-endian PCM.
        even_length = len(chunk.data) & ~1
        little = chunk.data[:even_length]
        network = bytearray(even_length)
        network[0::2], network[1::2] = little[1::2], little[0::2]
        result = []
        for pos in range(0, len(network), mtu & ~1):
            payload = bytes(network[pos : pos + (mtu & ~1)])
            result.append(self.packet(payload, self.audio_timestamp))
            self.audio_timestamp = (
                self.audio_timestamp + len(payload) // 2
            ) & 0xFFFFFFFF
        return result


@dataclass(eq=False)
class _Client:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    session_id: str = field(default_factory=lambda: f"{random.randrange(2**64):016x}")
    publication: Optional["_Publication"] = None
    playing: bool = False
    waiting_for_irap: bool = True
    transports: dict[int, tuple[str, object]] = field(default_factory=dict)
    video: _RtpTrack = field(default_factory=lambda: _RtpTrack(96, 90000))
    audio: _RtpTrack = field(default_factory=lambda: _RtpTrack(97, 8000))

    def close_transports(self) -> None:
        for kind, target in self.transports.values():
            if kind == "udp":
                sock, _address = target
                sock.close()
        self.transports.clear()


@dataclass(eq=False)
class _Publication:
    path: str
    stream: MediaStream
    subscription: MediaSubscription
    clients: set[_Client] = field(default_factory=set)
    parameter_sets: dict[int, VideoChunk] = field(default_factory=dict)
    task: Optional[asyncio.Task[None]] = None


class RtspServer:
    """One RTSP listener with independently managed stream publications.

    Paths are single URL-safe segments such as ``laundry`` or ``/cat-feeder``;
    both normalize to a leading-slash URL path. Duplicate publication paths are
    rejected instead of replacing a live camera stream accidentally.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8554) -> None:
        self.host, self.port = host, port
        self._server: Optional[asyncio.AbstractServer] = None
        self._publications: dict[str, _Publication] = {}
        self._connections: set[_Client] = set()

    @staticmethod
    def normalize_path(path: str) -> str:
        if not isinstance(path, str):
            raise TypeError("RTSP publication path must be a string")
        if not path or path != path.strip():
            raise ValueError("RTSP publication path must not be empty or padded")
        normalized = path if path.startswith("/") else "/" + path
        if normalized.count("/") != 1 or not _PUBLICATION_NAME.fullmatch(
            normalized[1:]
        ):
            raise ValueError(
                "RTSP publication path must be one URL-safe segment "
                "(letters, digits, '.', '_', '~', '-')"
            )
        return normalized

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def publications(self) -> tuple[str, ...]:
        return tuple(self._publications)

    def url(self, path: str) -> str:
        normalized = self.normalize_path(path)
        host = (
            f"[{self.host}]"
            if ":" in self.host and not self.host.startswith("[")
            else self.host
        )
        return f"rtsp://{host}:{self.port}{normalized}"

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        if self.port == 0:
            self.port = self._server.sockets[0].getsockname()[1]

    async def publish(self, path: str, stream: MediaStream) -> str:
        if self._server is None:
            raise RuntimeError("start RtspServer before publishing streams")
        normalized = self.normalize_path(path)
        if normalized in self._publications:
            raise ValueError(f"RTSP publication already exists: {normalized}")
        # Subscribe before returning so first camera parameter sets cannot
        # disappear in a task scheduling gap.
        publication = _Publication(normalized, stream, stream.subscribe())
        publication.task = asyncio.create_task(
            self._consume(publication), name=f"nexxt-rtsp-media:{normalized[1:]}"
        )
        self._publications[normalized] = publication
        return self.url(normalized)

    async def unpublish(self, path: str) -> None:
        normalized = self.normalize_path(path)
        publication = self._publications.pop(normalized, None)
        if publication is None:
            raise KeyError(f"RTSP publication does not exist: {normalized}")
        if publication.task is not None:
            publication.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await publication.task
        await publication.subscription.close()
        clients = list(publication.clients)
        publication.clients.clear()
        for client in clients:
            client.playing = False
            client.close_transports()
            client.writer.close()

    async def stop(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.close()
        # Connections which have not selected a publication are still owned by
        # the listener and must not survive a server shutdown. Close them
        # before waiting for the listener: asyncio's wait_closed() can wait
        # for handlers that are blocked reading from a still-open client.
        clients = list(self._connections)
        for client in clients:
            client.close_transports()
            client.writer.close()
        if server is not None:
            await server.wait_closed()
        for path in list(self._publications):
            await self.unpublish(path)

    async def _consume(self, publication: _Publication) -> None:
        try:
            async for chunk in publication.subscription:
                if isinstance(chunk, VideoChunk):
                    if chunk.is_parameter_set:
                        publication.parameter_sets[chunk.nal_type] = chunk
                    self._broadcast_video(publication, chunk)
                else:
                    self._broadcast_audio(publication, chunk)
        finally:
            await publication.subscription.close()

    def _send(self, client: _Client, track: int, packet: bytes) -> None:
        transport = client.transports.get(track)
        if transport is None:
            return
        kind, target = transport
        try:
            if kind == "tcp":
                transport_object = client.writer.transport
                if (
                    transport_object is not None
                    and transport_object.get_write_buffer_size()
                    > MAX_CLIENT_WRITE_BUFFER
                ):
                    LOG.warning("[warning] slow RTSP client disconnected")
                    client.playing = False
                    client.writer.close()
                    return
                channel = target
                client.writer.write(
                    b"$" + bytes((channel,)) + struct.pack(">H", len(packet)) + packet
                )
            else:
                sock, address = target
                sock.sendto(packet, address)
        except (ConnectionError, OSError):
            client.playing = False

    def _broadcast_video(self, publication: _Publication, chunk: VideoChunk) -> None:
        for client in tuple(publication.clients):
            if not client.playing or 0 not in client.transports:
                continue
            if client.waiting_for_irap:
                if not chunk.is_irap:
                    continue
                for nal_type in (32, 33, 34):
                    parameter = publication.parameter_sets.get(nal_type)
                    if parameter is not None:
                        for packet in client.video.hevc(parameter):
                            self._send(client, 0, packet)
                client.waiting_for_irap = False
            for packet in client.video.hevc(chunk):
                self._send(client, 0, packet)

    def _broadcast_audio(self, publication: _Publication, chunk: AudioChunk) -> None:
        for client in tuple(publication.clients):
            if client.playing and 1 in client.transports:
                for packet in client.audio.pcm(chunk):
                    self._send(client, 1, packet)

    @staticmethod
    def _sdp(publication: _Publication) -> bytes:
        fmtp = ""
        names = ((32, "sprop-vps"), (33, "sprop-sps"), (34, "sprop-pps"))
        values = [
            f"{name}={base64.b64encode(publication.parameter_sets[k].payload).decode()}"
            for k, name in names
            if k in publication.parameter_sets
        ]
        if values:
            fmtp = "a=fmtp:96 " + ";".join(values) + "\r\n"
        return (
            "v=0\r\n"
            "o=- 0 0 IN IP4 127.0.0.1\r\n"
            "s=Nexxt camera\r\n"
            "t=0 0\r\n"
            "a=control:*\r\n"
            "m=video 0 RTP/AVP 96\r\n"
            "a=rtpmap:96 H265/90000\r\n"
            f"{fmtp}"
            "a=control:trackID=0\r\n"
            "m=audio 0 RTP/AVP 97\r\n"
            "a=rtpmap:97 L16/8000/1\r\n"
            "a=control:trackID=1\r\n"
        ).encode()

    async def _response(
        self,
        client: _Client,
        cseq: str,
        status: str = "200 OK",
        headers: Optional[dict[str, str]] = None,
        body: bytes = b"",
    ) -> None:
        fields = {"CSeq": cseq, "Server": "nexxt-lan"}
        fields.update(headers or {})
        if body:
            fields["Content-Length"] = str(len(body))
        head = (
            f"RTSP/1.0 {status}\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in fields.items())
            + "\r\n"
        )
        client.writer.write(head.encode() + body)
        await client.writer.drain()

    @staticmethod
    def _uri_path(uri: str) -> Optional[str]:
        split = urlsplit(uri)
        if split.query or split.fragment:
            return None
        try:
            return unquote(split.path)
        except UnicodeDecodeError:
            return None

    def _publication_for_uri(
        self, uri: str, *, track: bool = False
    ) -> tuple[Optional[_Publication], Optional[int]]:
        path = self._uri_path(uri)
        if path is None:
            return None, None
        if not track:
            # Content-Base ends in a slash, and ffmpeg consequently sends an
            # aggregate PLAY to ``/name/``. Treat that as the publication URL.
            return self._publications.get(path.rstrip("/") or "/"), None
        match = re.fullmatch(r"(/[^/]+)/trackID=([01])", path)
        if match is None:
            return None, None
        return self._publications.get(match.group(1)), int(match.group(2))

    def _bind_client(self, client: _Client, publication: _Publication) -> bool:
        if client.publication is not None and client.publication is not publication:
            return False
        if client.publication is None:
            client.publication = publication
            publication.clients.add(client)
        return True

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        client = _Client(reader, writer)
        self._connections.add(client)
        peer = writer.get_extra_info("peername")
        LOG.info("[rtsp] client connected: %s", peer)
        try:
            while True:
                first = await reader.readexactly(1)
                if first == b"$":
                    interleaved = await reader.readexactly(3)
                    await reader.readexactly(struct.unpack(">H", interleaved[1:3])[0])
                    continue
                request_line = first + await reader.readline()
                parts = request_line.decode("latin1").strip().split()
                if len(parts) != 3:
                    break
                method, uri, _version = parts
                headers: dict[str, str] = {}
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                    key, _, value = line.decode("latin1").partition(":")
                    headers[key.lower()] = value.strip()
                length = int(headers.get("content-length", "0"))
                if length:
                    await reader.readexactly(length)
                cseq = headers.get("cseq", "0")
                if method == "OPTIONS":
                    await self._response(
                        client,
                        cseq,
                        headers={
                            "Public": "OPTIONS, DESCRIBE, SETUP, PLAY, GET_PARAMETER, TEARDOWN"
                        },
                    )
                elif method == "DESCRIBE":
                    publication, _ = self._publication_for_uri(uri)
                    if publication is None:
                        await self._response(client, cseq, "404 Not Found")
                    elif not self._bind_client(client, publication):
                        await self._response(
                            client, cseq, "459 Aggregate Operation Not Allowed"
                        )
                    else:
                        await self._response(
                            client,
                            cseq,
                            headers={
                                "Content-Type": "application/sdp",
                                "Content-Base": self.url(publication.path) + "/",
                            },
                            body=self._sdp(publication),
                        )
                elif method == "SETUP":
                    publication, track = self._publication_for_uri(uri, track=True)
                    if publication is None or track is None:
                        await self._response(client, cseq, "404 Not Found")
                        continue
                    if not self._bind_client(client, publication):
                        await self._response(
                            client, cseq, "459 Aggregate Operation Not Allowed"
                        )
                        continue
                    transport = headers.get("transport", "")
                    tcp = re.search(r"interleaved=(\d+)(?:-(\d+))?", transport, re.I)
                    udp = re.search(r"client_port=(\d+)(?:-(\d+))?", transport, re.I)
                    if tcp:
                        channel = int(tcp.group(1))
                        client.transports[track] = ("tcp", channel)
                        rtp_track = client.video if track == 0 else client.audio
                        response_transport = (
                            f"RTP/AVP/TCP;unicast;interleaved={channel}-{channel + 1};"
                            f"ssrc={rtp_track.ssrc:08X}"
                        )
                    elif udp:
                        udp_peer = writer.get_extra_info("peername")
                        family = (
                            socket.AF_INET6 if ":" in udp_peer[0] else socket.AF_INET
                        )
                        rtp_socket = socket.socket(family, socket.SOCK_DGRAM)
                        rtp_socket.bind((self.host, 0))
                        server_port = rtp_socket.getsockname()[1]
                        client.transports[track] = (
                            "udp",
                            (rtp_socket, (udp_peer[0], int(udp.group(1)))),
                        )
                        response_transport = (
                            "RTP/AVP;unicast;"
                            f"client_port={udp.group(1)}-{udp.group(2) or int(udp.group(1)) + 1};"
                            f"server_port={server_port}-{server_port + 1}"
                        )
                    else:
                        await self._response(client, cseq, "461 Unsupported Transport")
                        continue
                    await self._response(
                        client,
                        cseq,
                        headers={
                            "Session": client.session_id + ";timeout=60",
                            "Transport": response_transport,
                        },
                    )
                elif method == "PLAY":
                    publication, _ = self._publication_for_uri(uri)
                    if publication is None:
                        await self._response(client, cseq, "404 Not Found")
                    elif client.publication is not publication:
                        await self._response(client, cseq, "454 Session Not Found")
                    else:
                        client.playing = True
                        client.waiting_for_irap = True
                        await self._response(
                            client, cseq, headers={"Session": client.session_id}
                        )
                elif method == "GET_PARAMETER":
                    await self._response(
                        client, cseq, headers={"Session": client.session_id}
                    )
                elif method == "TEARDOWN":
                    await self._response(
                        client, cseq, headers={"Session": client.session_id}
                    )
                    break
                else:
                    await self._response(client, cseq, "405 Method Not Allowed")
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            self._connections.discard(client)
            if client.publication is not None:
                client.publication.clients.discard(client)
            client.close_transports()
            writer.close()
            LOG.info("[rtsp] client disconnected: %s", peer)


class RtspPublisher:
    """Deprecated one-path compatibility wrapper around :class:`RtspServer`."""

    def __init__(
        self, host: str = "127.0.0.1", port: int = 8554, path: str = "/stream"
    ) -> None:
        self.host, self.port = host, port
        self.path = RtspServer.normalize_path(path)
        self._rtsp_server: Optional[RtspServer] = None

    @property
    def _server(self) -> Optional[asyncio.AbstractServer]:
        return self._rtsp_server._server if self._rtsp_server is not None else None

    @property
    def url(self) -> str:
        if self._rtsp_server is not None:
            return self._rtsp_server.url(self.path)
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"rtsp://{host}:{self.port}{self.path}"

    async def start(self, stream: MediaStream) -> str:
        if self._rtsp_server is None:
            self._rtsp_server = RtspServer(self.host, self.port)
            await self._rtsp_server.start()
            self.port = self._rtsp_server.port
            return await self._rtsp_server.publish(self.path, stream)
        return self.url

    async def publish(self, stream: MediaStream) -> str:
        return await self.start(stream)

    async def stop(self) -> None:
        if self._rtsp_server is not None:
            await self._rtsp_server.stop()
            self._rtsp_server = None


class RtspPublisherThread:
    """Synchronous lifecycle adapter for the current blocking camera CLI."""

    def __init__(self, publisher: RtspPublisher) -> None:
        self.publisher = publisher
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None

    def start(self, stream: MediaStream) -> str:
        def run() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self.publisher.start(stream))
            except BaseException as exc:
                self._error = exc
                self._ready.set()
                loop.close()
                return
            self._ready.set()
            loop.run_forever()
            loop.run_until_complete(self.publisher.stop())
            loop.close()

        self._thread = threading.Thread(target=run, name="nexxt-rtsp", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5)
        if self._error is not None:
            raise RuntimeError(
                f"could not start RTSP publisher: {self._error}"
            ) from self._error
        if not self._ready.is_set():
            raise RuntimeError("timed out starting RTSP publisher")
        return self.publisher.url

    def stop(self) -> None:
        loop, thread = self._loop, self._thread
        if loop is None or thread is None or not thread.is_alive():
            return
        future = asyncio.run_coroutine_threadsafe(self.publisher.stop(), loop)
        with contextlib.suppress(Exception):
            future.result(timeout=3)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=3)
