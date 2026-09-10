import struct
import shutil
import threading
import time

import pytest

from nexxt_lan import (
    ANNEXB_START_CODE,
    HevcAssembler,
    MediaOutput,
    PlaybackPipe,
    parse_media_record,
)


class FakeStdin:
    def __init__(self, *, fail=False, block=None):
        self.data = bytearray()
        self.fail = fail
        self.block = block
        self.closed = False

    def write(self, data):
        if self.fail:
            raise BrokenPipeError("fake pipe closed")
        if self.block is not None:
            self.block.wait(timeout=1)
        self.data.extend(data)
        return len(data)

    def flush(self):
        if self.fail:
            raise BrokenPipeError("fake pipe closed")

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, stdin):
        self.stdin = stdin
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


def fake_factory(stdin):
    def factory(*args, **kwargs):
        return FakeProcess(stdin)

    return factory


def media_record(extension: bytes, payload: bytes) -> bytes:
    return (
        bytes(16)
        + struct.pack("<Q", len(extension))
        + extension
        + struct.pack("<I", len(payload))
        + payload
    )


@pytest.mark.parametrize("extension", [b"", b"12345678"])
def test_parse_media_record_variable_extension(extension):
    payload = bytes(12) + b"codec data"
    parsed = parse_media_record(media_record(extension, payload))
    assert parsed.extension == extension
    assert parsed.payload == payload


def test_parse_media_record_requires_exact_payload_length():
    record = media_record(b"", b"payload")
    with pytest.raises(ValueError, match="payload length mismatch"):
        parse_media_record(record + b"trailing")


def test_parse_media_record_rejects_truncated_extension():
    record = bytes(16) + struct.pack("<Q", 100) + bytes(4)
    with pytest.raises(ValueError, match="extension exceeds record"):
        parse_media_record(record)


def test_hevc_assembler_passes_complete_nal_with_start_code():
    assembler = HevcAssembler()
    vps = b"\x40\x01\xaa\xbb"
    assert assembler.feed(vps) == [ANNEXB_START_CODE + vps]
    assert assembler.complete_nals == 1
    assert assembler.reassembled_fu == 0


def test_hevc_assembler_reassembles_type_49_fu():
    assembler = HevcAssembler()
    assert assembler.feed(b"\x62\x01\x93start") == []
    assert assembler.feed(b"\x62\x01\x13middle") == []
    result = assembler.feed(b"\x62\x01\x53end")

    # FU type 19 reconstructs byte 0 as (0x62 & 0x81) | (19 << 1) == 0x26.
    assert result == [ANNEXB_START_CODE + b"\x26\x01startmiddleend"]
    assert assembler.reassembled_fu == 1
    assert assembler.anomalies == 0


def test_hevc_assembler_discards_continuation_without_start():
    assembler = HevcAssembler()
    assert assembler.feed(b"\x62\x01\x13orphan") == []
    assert assembler.anomalies == 1


def test_media_output_extracts_hevc_and_pcm_without_playback(tmp_path):
    output = MediaOutput(play=False, ffplay_path=None, dump_dir=tmp_path)
    vps = b"\x40\x01video"
    pcm = b"\x04\x00\xfe\xff"
    output.feed(1, 0, media_record(b"12345678", bytes(12) + vps))
    output.feed(2, 0, media_record(b"", bytes(12) + pcm))
    output.close()

    assert (tmp_path / "video.h265").read_bytes() == ANNEXB_START_CODE + vps
    assert (tmp_path / "audio.s16le").read_bytes() == pcm
    assert output.assembler.complete_nals == 1
    assert output.audio_chunks == 1
    assert output.audio_bytes == len(pcm)


def test_playback_pipe_writer_and_shutdown_leave_no_process():
    cat = shutil.which("cat")
    if cat is None:
        pytest.skip("cat is unavailable")
    pipe = PlaybackPipe(label="test", command=[cat], max_chunks=2)
    pipe.offer(b"one")
    pipe.offer(b"two")
    pipe.close()

    assert pipe.process.poll() is not None
    assert not pipe._thread.is_alive()


def test_video_writer_preserves_byte_exact_nal_order():
    stdin = FakeStdin()
    pipe = PlaybackPipe(
        label="test-video",
        command=["fake"],
        max_bytes=4096,
        codec_safe=True,
        process_factory=fake_factory(stdin),
    )
    nals = [
        ANNEXB_START_CODE + b"\x40\x01vps",
        ANNEXB_START_CODE + b"\x42\x01sps",
        ANNEXB_START_CODE + b"\x44\x01pps",
        ANNEXB_START_CODE + b"\x02\x01frame",
    ]
    for nal in nals:
        pipe.offer(nal)
    deadline = time.monotonic() + 1
    while len(stdin.data) != sum(map(len, nals)) and time.monotonic() < deadline:
        time.sleep(0.005)
    pipe.close()
    assert bytes(stdin.data) == b"".join(nals)
    assert pipe.dropped == 0


def test_video_overflow_waits_for_irap_and_restarts_with_parameter_sets():
    unblock = threading.Event()
    stdin = FakeStdin(block=unblock)
    pipe = PlaybackPipe(
        label="test-video",
        command=["fake"],
        max_bytes=32,
        codec_safe=True,
        process_factory=fake_factory(stdin),
    )
    vps = ANNEXB_START_CODE + b"\x40\x01v"
    sps = ANNEXB_START_CODE + b"\x42\x01s"
    pps = ANNEXB_START_CODE + b"\x44\x01p"
    pframe = ANNEXB_START_CODE + b"\x02\x01inter"
    idr = ANNEXB_START_CODE + b"\x26\x01idr"
    for nal in (vps, sps, pps, pframe, pframe):
        pipe.offer(nal)
    assert pipe.overflow_events == 1
    assert pipe._desynchronised
    pipe.offer(idr)
    assert not pipe._desynchronised
    assert pipe.decoder_resyncs == 1
    # Enqueue remains prompt even while the writer is deliberately blocked.
    started = time.monotonic()
    pipe.offer(pframe)
    assert time.monotonic() - started < 0.05
    unblock.set()
    pipe.close()


def test_audio_command_uses_channel_layout_not_ac():
    output = MediaOutput(play=True, ffplay_path="fake-ffplay", dump_dir=None)
    command = output.audio_pipe._command
    assert ["-f", "s16le"] == command[command.index("-f") : command.index("-f") + 2]
    assert ["-ar", "8000"] == command[command.index("-ar") : command.index("-ar") + 2]
    assert ["-ch_layout", "mono"] == command[
        command.index("-ch_layout") : command.index("-ch_layout") + 2
    ]
    assert "-ac" not in command
    output.close()


def test_broken_pipe_stops_later_feeds_cleanly():
    stdin = FakeStdin(fail=True)
    pipe = PlaybackPipe(
        label="test-audio",
        command=["fake"],
        max_bytes=4096,
        process_factory=fake_factory(stdin),
    )
    pipe.offer(b"first")
    deadline = time.monotonic() + 1
    while not pipe._broken and time.monotonic() < deadline:
        time.sleep(0.005)
    assert pipe._broken
    pipe.offer(b"later")
    pipe.close()
    assert pipe.process.stdin.closed
