"""Backend-neutral media boundary for decrypted Nexxt camera records.

Transport code ends at :meth:`MediaPipeline.feed_record`.  Everything emitted
from the pipeline is ordinary HEVC Annex-B or PCM and contains no Tuya/KCP
state.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import AsyncIterator, Optional, Protocol, Union, runtime_checkable

LOG = logging.getLogger("nexxt_lan")

ANNEXB_START_CODE = b"\x00\x00\x00\x01"
HEVC_FU_NAL_TYPE = 49
MEDIA_SUBHEADER_SIZE = 12
HEVC_CODEC = "hevc"
PCM_CODEC = "pcm_s16le"
PCM_SAMPLE_RATE = 8000
PCM_CHANNELS = 1


@dataclass(frozen=True)
class MediaRecord:
    extension: bytes
    payload: bytes


@dataclass(frozen=True)
class VideoChunk:
    """One complete HEVC NAL unit in Annex-B representation."""

    data: bytes
    timestamp_ns: int
    codec: str = HEVC_CODEC

    @property
    def nal_type(self) -> int:
        offset = 4 if self.data.startswith(ANNEXB_START_CODE) else 0
        return (self.data[offset] >> 1) & 0x3F

    @property
    def payload(self) -> bytes:
        """NAL bytes without an Annex-B start code."""
        if self.data.startswith(ANNEXB_START_CODE):
            return self.data[4:]
        if self.data.startswith(b"\x00\x00\x01"):
            return self.data[3:]
        return self.data

    @property
    def is_parameter_set(self) -> bool:
        return self.nal_type in (32, 33, 34)

    @property
    def is_irap(self) -> bool:
        return 16 <= self.nal_type <= 23


@dataclass(frozen=True)
class AudioChunk:
    """Signed little-endian PCM samples with explicit format metadata."""

    data: bytes
    timestamp_ns: int
    codec: str = PCM_CODEC
    sample_rate: int = PCM_SAMPLE_RATE
    channels: int = PCM_CHANNELS
    sample_width: int = 2


MediaChunk = Union[VideoChunk, AudioChunk]


def parse_media_record(message: bytes) -> MediaRecord:
    """Parse the variable-length Tuya media envelope exactly."""
    if len(message) < 28:
        raise ValueError(f"media record too short: {len(message)} bytes")
    ext_len = struct.unpack_from("<Q", message, 16)[0]
    if ext_len > len(message) - 28:
        raise ValueError(
            f"media extension exceeds record: ext_len={ext_len} len={len(message)}"
        )
    len_off = 24 + ext_len
    payload_len = struct.unpack_from("<I", message, len_off)[0]
    payload_off = len_off + 4
    payload_end = payload_off + payload_len
    if payload_end != len(message):
        raise ValueError(
            "media payload length mismatch: "
            f"payload_off={payload_off} payload_len={payload_len} "
            f"record_len={len(message)}"
        )
    return MediaRecord(message[24:len_off], message[payload_off:payload_end])


class HevcAssembler:
    """Reassemble Tuya's HEVC NAL and RFC-style type-49 FU payloads."""

    def __init__(self) -> None:
        self._fu_buffer: Optional[bytearray] = None
        self._fu_type: Optional[int] = None
        self.complete_nals = 0
        self.reassembled_fu = 0
        self.anomalies = 0

    def _anomaly(self, message: str, *args: object) -> None:
        self.anomalies += 1
        LOG.debug("[debug] HEVC FU anomaly: " + message, *args)

    def feed(self, data: bytes) -> list[bytes]:
        if len(data) < 2:
            self._anomaly("packet too short len=%d", len(data))
            return []
        nal_type = (data[0] >> 1) & 0x3F
        if nal_type != HEVC_FU_NAL_TYPE:
            if self._fu_buffer is not None:
                self._anomaly(
                    "complete NAL type=%d interrupted unfinished FU type=%d",
                    nal_type,
                    self._fu_type,
                )
                self._fu_buffer = None
                self._fu_type = None
            self.complete_nals += 1
            return [ANNEXB_START_CODE + data]
        if len(data) < 3:
            self._anomaly("FU packet too short len=%d", len(data))
            return []
        fu_header = data[2]
        start, end, fu_type = (
            bool(fu_header & 0x80),
            bool(fu_header & 0x40),
            fu_header & 0x3F,
        )
        if start:
            if self._fu_buffer is not None:
                self._anomaly(
                    "new START type=%d replaced unfinished FU type=%d",
                    fu_type,
                    self._fu_type,
                )
            self._fu_buffer = bytearray(((data[0] & 0x81) | (fu_type << 1), data[1]))
            self._fu_buffer.extend(data[3:])
            self._fu_type = fu_type
            if not end:
                return []
        else:
            if self._fu_buffer is None:
                self._anomaly(
                    "%s without START type=%d", "END" if end else "CONT", fu_type
                )
                return []
            if fu_type != self._fu_type:
                self._anomaly(
                    "FU type changed expected=%d received=%d", self._fu_type, fu_type
                )
                self._fu_buffer = None
                self._fu_type = None
                return []
            self._fu_buffer.extend(data[3:])
            if not end:
                return []
        assert self._fu_buffer is not None
        complete = ANNEXB_START_CODE + bytes(self._fu_buffer)
        self._fu_buffer = None
        self._fu_type = None
        self.reassembled_fu += 1
        return [complete]


@runtime_checkable
class MediaSink(Protocol):
    """Synchronous, non-blocking sink called by the camera receive loop."""

    def start(self) -> None: ...
    def on_video(self, chunk: VideoChunk) -> None: ...
    def on_audio(self, chunk: AudioChunk) -> None: ...
    def close(self) -> None: ...


class MediaPipeline:
    """Convert decrypted records to neutral chunks and fan them out."""

    def __init__(self, sinks: tuple[MediaSink, ...] | list[MediaSink] = ()) -> None:
        self.assembler = HevcAssembler()
        self.sinks = list(sinks)
        self.video_chunks = 0
        self.audio_chunks = 0
        self.audio_bytes = 0
        self.bad_records: Counter[int] = Counter()
        self._closed = False
        started: list[MediaSink] = []
        try:
            for sink in self.sinks:
                sink.start()
                started.append(sink)
        except Exception:
            for sink in reversed(started):
                sink.close()
            raise

    def _video(self, chunk: VideoChunk) -> None:
        for sink in self.sinks:
            try:
                sink.on_video(chunk)
            except Exception:
                LOG.exception("[warning] media video sink failed")

    def _audio(self, chunk: AudioChunk) -> None:
        for sink in self.sinks:
            try:
                sink.on_audio(chunk)
            except Exception:
                LOG.exception("[warning] media audio sink failed")

    def feed_record(self, conv: int, message_index: int, message: bytes) -> None:
        if self._closed:
            return
        try:
            record = parse_media_record(message)
            if len(record.payload) < MEDIA_SUBHEADER_SIZE:
                raise ValueError(
                    f"media payload too short for subheader: {len(record.payload)}"
                )
        except ValueError as exc:
            self.bad_records[conv] += 1
            LOG.debug(
                "[debug] media envelope rejected conv=%d msg=%d: %s",
                conv,
                message_index,
                exc,
            )
            return
        data = record.payload[MEDIA_SUBHEADER_SIZE:]
        timestamp_ns = time.monotonic_ns()
        if conv == 1:
            for nal in self.assembler.feed(data):
                self.video_chunks += 1
                self._video(VideoChunk(nal, timestamp_ns))
        elif conv == 2:
            self.audio_chunks += 1
            self.audio_bytes += len(data)
            self._audio(AudioChunk(data, timestamp_ns))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for sink in reversed(self.sinks):
            try:
                sink.close()
            except Exception:
                LOG.exception("[warning] media sink shutdown failed")


_CLOSED = object()


class MediaSubscription(AsyncIterator[MediaChunk]):
    def __init__(self, stream: "MediaStream", queue: asyncio.Queue[object]) -> None:
        self._stream = stream
        self._queue = queue

    def __aiter__(self) -> "MediaSubscription":
        return self

    async def __anext__(self) -> MediaChunk:
        item = await self._queue.get()
        if item is _CLOSED:
            raise StopAsyncIteration
        assert isinstance(item, (VideoChunk, AudioChunk))
        return item

    async def close(self) -> None:
        self._stream._unsubscribe(self._queue)


class MediaStream:
    """Thread-safe broadcast sink with an async-iterator consumer API."""

    def __init__(self, *, subscriber_queue_size: int = 512) -> None:
        self._queue_size = subscriber_queue_size
        self._subscribers: dict[asyncio.Queue[object], asyncio.AbstractEventLoop] = {}
        self._lock = threading.Lock()
        self._closed = False

    def start(self) -> None:
        pass

    def subscribe(self) -> MediaSubscription:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[object] = asyncio.Queue(self._queue_size)
        with self._lock:
            if self._closed:
                queue.put_nowait(_CLOSED)
            else:
                self._subscribers[queue] = loop
        return MediaSubscription(self, queue)

    @staticmethod
    def _offer(queue: asyncio.Queue[object], item: object) -> None:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait(item)

    def _publish(self, chunk: MediaChunk) -> None:
        with self._lock:
            subscribers = list(self._subscribers.items())
        for queue, loop in subscribers:
            try:
                loop.call_soon_threadsafe(self._offer, queue, chunk)
            except RuntimeError:
                self._unsubscribe(queue)

    def on_video(self, chunk: VideoChunk) -> None:
        self._publish(chunk)

    def on_audio(self, chunk: AudioChunk) -> None:
        self._publish(chunk)

    def _unsubscribe(self, queue: asyncio.Queue[object]) -> None:
        with self._lock:
            self._subscribers.pop(queue, None)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            subscribers = list(self._subscribers.items())
            self._subscribers.clear()
        for queue, loop in subscribers:
            if not loop.is_closed():
                loop.call_soon_threadsafe(self._offer, queue, _CLOSED)
