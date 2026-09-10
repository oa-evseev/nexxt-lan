import asyncio
import struct

from nexxt.media import (
    ANNEXB_START_CODE,
    AudioChunk,
    MediaPipeline,
    MediaStream,
    VideoChunk,
)


def media_record(payload: bytes) -> bytes:
    return bytes(16) + struct.pack("<Q", 0) + struct.pack("<I", len(payload)) + payload


class RecordingSink:
    def __init__(self):
        self.events = []

    def start(self):
        self.events.append("start")

    def on_video(self, chunk):
        self.events.append(chunk)

    def on_audio(self, chunk):
        self.events.append(chunk)

    def close(self):
        self.events.append("close")


def test_pipeline_routes_typed_video_audio_and_lifecycle():
    sink = RecordingSink()
    pipeline = MediaPipeline([sink])
    pipeline.feed_record(1, 0, media_record(bytes(12) + b"\x40\x01vps"))
    pipeline.feed_record(2, 0, media_record(bytes(12) + b"\x01\x00\xff\xff"))
    pipeline.close()

    assert sink.events[0] == "start"
    assert sink.events[-1] == "close"
    video, audio = sink.events[1:3]
    assert isinstance(video, VideoChunk)
    assert video.data == ANNEXB_START_CODE + b"\x40\x01vps"
    assert video.codec == "hevc"
    assert video.nal_type == 32
    assert isinstance(audio, AudioChunk)
    assert audio.codec == "pcm_s16le"
    assert (audio.sample_rate, audio.channels, audio.sample_width) == (8000, 1, 2)


def test_async_media_stream_broadcasts_without_network():
    async def exercise():
        stream = MediaStream()
        subscription = stream.subscribe()
        video = VideoChunk(ANNEXB_START_CODE + b"\x26\x01idr", 1)
        audio = AudioChunk(b"\x01\x00", 2)
        stream.on_video(video)
        stream.on_audio(audio)
        assert await subscription.__anext__() == video
        assert await subscription.__anext__() == audio
        stream.close()
        try:
            await subscription.__anext__()
        except StopAsyncIteration:
            pass
        else:
            raise AssertionError("closed stream did not end subscription")

    asyncio.run(exercise())
