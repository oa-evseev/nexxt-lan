import asyncio
import base64
import shutil
import struct
import subprocess
import time

import pytest

from nexxt.media import ANNEXB_START_CODE, AudioChunk, MediaStream, VideoChunk
from nexxt.rtsp import RtspPublisher, RtspServer


async def request(reader, writer, port, method, target, cseq, headers=()):
    lines = [f"{method} rtsp://127.0.0.1:{port}{target} RTSP/1.0", f"CSeq: {cseq}"]
    lines.extend(headers)
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await writer.drain()
    status = await reader.readline()
    response_headers = {}
    while True:
        line = await reader.readline()
        if line == b"\r\n":
            break
        key, value = line.decode().split(":", 1)
        response_headers[key.lower()] = value.strip()
    body = await reader.readexactly(int(response_headers.get("content-length", 0)))
    return status, response_headers, body


def test_rtsp_url_uses_configured_bind_address():
    assert RtspPublisher("192.168.10.5", 8554).url == "rtsp://192.168.10.5:8554/stream"
    assert RtspPublisher("::1", 8554).url == "rtsp://[::1]:8554/stream"


async def setup_and_play(server, path, *, cseq=1):
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    status, _, _ = await request(reader, writer, server.port, "DESCRIBE", path, cseq)
    assert status.startswith(b"RTSP/1.0 200")
    status, headers, _ = await request(
        reader,
        writer,
        server.port,
        "SETUP",
        f"{path}/trackID=0",
        cseq + 1,
        ["Transport: RTP/AVP/TCP;unicast;interleaved=0-1"],
    )
    assert status.startswith(b"RTSP/1.0 200")
    session = headers["session"].split(";", 1)[0]
    status, _, _ = await request(
        reader, writer, server.port, "PLAY", path, cseq + 2, [f"Session: {session}"]
    )
    assert status.startswith(b"RTSP/1.0 200")
    return reader, writer


async def read_rtp(reader):
    assert await reader.readexactly(1) == b"$"
    channel = (await reader.readexactly(1))[0]
    size = struct.unpack(">H", await reader.readexactly(2))[0]
    return channel, await reader.readexactly(size)


def test_rtsp_server_multiple_publications_are_isolated():
    async def exercise():
        laundry, feeder = MediaStream(), MediaStream()
        server = RtspServer("127.0.0.1", 0)
        await server.start()
        assert await server.publish("laundry", laundry) == (
            f"rtsp://127.0.0.1:{server.port}/laundry"
        )
        assert await server.publish("/cat-feeder", feeder) == (
            f"rtsp://127.0.0.1:{server.port}/cat-feeder"
        )
        with pytest.raises(ValueError, match="already exists"):
            await server.publish("laundry", MediaStream())

        sets_a = (b"\x40\x01a-vps", b"\x42\x01a-sps", b"\x44\x01a-pps")
        sets_b = (b"\x40\x01b-vps", b"\x42\x01b-sps", b"\x44\x01b-pps")
        for index, nal in enumerate(sets_a):
            laundry.on_video(VideoChunk(ANNEXB_START_CODE + nal, index + 1))
        for index, nal in enumerate(sets_b):
            feeder.on_video(VideoChunk(ANNEXB_START_CODE + nal, index + 1))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        reader_a, writer_a = await asyncio.open_connection("127.0.0.1", server.port)
        status, _, sdp_a = await request(
            reader_a, writer_a, server.port, "DESCRIBE", "/laundry", 1
        )
        assert status.startswith(b"RTSP/1.0 200")
        assert base64.b64encode(sets_a[0]) in sdp_a
        assert base64.b64encode(sets_b[0]) not in sdp_a

        reader_b, writer_b = await setup_and_play(server, "/cat-feeder", cseq=10)
        status, headers_a, _ = await request(
            reader_a,
            writer_a,
            server.port,
            "SETUP",
            "/laundry/trackID=0",
            2,
            ["Transport: RTP/AVP/TCP;unicast;interleaved=0-1"],
        )
        assert status.startswith(b"RTSP/1.0 200")
        session_a = headers_a["session"].split(";", 1)[0]
        await request(
            reader_a,
            writer_a,
            server.port,
            "PLAY",
            "/laundry",
            3,
            [f"Session: {session_a}"],
        )

        publication_a = server._publications["/laundry"]
        publication_b = server._publications["/cat-feeder"]
        client_a = next(iter(publication_a.clients))
        client_b = next(iter(publication_b.clients))
        assert client_a.video is not client_b.video
        feeder_sequence = client_b.video.sequence

        # Each late client gets only its own parameter sets followed by its
        # stream's next IRAP. Publishing A must not advance B's RTP state.
        laundry.on_video(VideoChunk(ANNEXB_START_CODE + b"\x26\x01a-idr", 10))
        assert client_b.video.sequence == feeder_sequence
        feeder.on_video(VideoChunk(ANNEXB_START_CODE + b"\x26\x01b-idr", 11))
        received_a = [await read_rtp(reader_a) for _ in range(4)]
        received_b = [await read_rtp(reader_b) for _ in range(4)]
        assert [packet[1][12:] for packet in received_a] == [
            *sets_a,
            b"\x26\x01a-idr",
        ]
        assert [packet[1][12:] for packet in received_b] == [
            *sets_b,
            b"\x26\x01b-idr",
        ]
        assert all(channel == 0 for channel, _packet in received_a + received_b)

        writer_a.close()
        writer_b.close()
        await writer_a.wait_closed()
        await writer_b.wait_closed()
        await server.stop()
        laundry.close()
        feeder.close()

    asyncio.run(exercise())


def test_unpublish_is_path_scoped_and_unknown_paths_are_404():
    async def exercise():
        laundry, bedroom = MediaStream(), MediaStream()
        server = RtspServer("127.0.0.1", 0)
        await server.start()
        await server.publish("laundry", laundry)
        await server.publish("bedroom", bedroom)

        unknown_reader, unknown_writer = await asyncio.open_connection(
            "127.0.0.1", server.port
        )
        status, _, _ = await request(
            unknown_reader, unknown_writer, server.port, "DESCRIBE", "/missing", 1
        )
        assert status.startswith(b"RTSP/1.0 404")
        unknown_writer.close()
        await unknown_writer.wait_closed()

        for stream, suffix in ((laundry, b"a"), (bedroom, b"b")):
            for nal_type, name in (
                (b"\x40\x01", b"vps"),
                (b"\x42\x01", b"sps"),
                (b"\x44\x01", b"pps"),
            ):
                stream.on_video(
                    VideoChunk(ANNEXB_START_CODE + nal_type + suffix + name, 1)
                )
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        reader_a, writer_a = await setup_and_play(server, "/laundry", cseq=10)
        reader_b, writer_b = await setup_and_play(server, "/bedroom", cseq=20)

        await server.unpublish("laundry")
        assert "/laundry" not in server.publications
        assert "/bedroom" in server.publications
        assert await asyncio.wait_for(reader_a.read(1), timeout=1) == b""

        # Bedroom remains live and still has its own late-join parameter cache.
        bedroom.on_video(VideoChunk(ANNEXB_START_CODE + b"\x26\x01b-idr", 2))
        packets_b = [await read_rtp(reader_b) for _ in range(4)]
        assert packets_b[-1][1][12:] == b"\x26\x01b-idr"
        with pytest.raises(KeyError, match="does not exist"):
            await server.unpublish("laundry")

        await server.stop()
        assert await asyncio.wait_for(reader_b.read(1), timeout=1) == b""
        assert not server.running
        assert server.publications == ()
        laundry.close()
        bedroom.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("path", ["", " two", "two ", "/nested/path", "/", "a?b"])
def test_rtsp_publication_paths_are_normalized_and_validated(path):
    with pytest.raises(ValueError):
        RtspServer.normalize_path(path)
    assert RtspServer.normalize_path("cat-feeder") == "/cat-feeder"


def test_rtsp_startup_sdp_late_join_and_shutdown():
    async def exercise():
        stream = MediaStream()
        publisher = RtspPublisher("127.0.0.1", 0)
        url = await publisher.start(stream)
        assert url == f"rtsp://127.0.0.1:{publisher.port}/stream"

        vps = VideoChunk(ANNEXB_START_CODE + b"\x40\x01vps", 1)
        sps = VideoChunk(ANNEXB_START_CODE + b"\x42\x01sps", 2)
        pps = VideoChunk(ANNEXB_START_CODE + b"\x44\x01pps", 3)
        for chunk in (vps, sps, pps):
            stream.on_video(chunk)
        await asyncio.sleep(0)

        reader, writer = await asyncio.open_connection("127.0.0.1", publisher.port)
        status, _, sdp = await request(
            reader,
            writer,
            publisher.port,
            "DESCRIBE",
            "/stream",
            1,
            ["Accept: application/sdp"],
        )
        assert status.startswith(b"RTSP/1.0 200")
        assert b"H265/90000" in sdp and b"L16/8000/1" in sdp
        assert base64.b64encode(vps.payload) in sdp

        status, headers, _ = await request(
            reader,
            writer,
            publisher.port,
            "SETUP",
            "/stream/trackID=0",
            2,
            ["Transport: RTP/AVP/TCP;unicast;interleaved=0-1"],
        )
        assert status.startswith(b"RTSP/1.0 200")
        session = headers["session"].split(";", 1)[0]
        status, _, _ = await request(
            reader,
            writer,
            publisher.port,
            "PLAY",
            "/stream",
            3,
            [f"Session: {session}"],
        )
        assert status.startswith(b"RTSP/1.0 200")

        # Inter pictures are withheld for a late joiner.  At the next IRAP,
        # VPS/SPS/PPS are injected first and then the IRAP is sent.
        stream.on_video(VideoChunk(ANNEXB_START_CODE + b"\x02\x01inter", 4))
        await asyncio.sleep(0.01)
        stream.on_video(VideoChunk(ANNEXB_START_CODE + b"\x26\x01idr", 5))
        nal_types = []
        for _ in range(4):
            assert await reader.readexactly(1) == b"$"
            channel = (await reader.readexactly(1))[0]
            size = struct.unpack(">H", await reader.readexactly(2))[0]
            packet = await reader.readexactly(size)
            assert channel == 0
            nal_types.append((packet[12] >> 1) & 0x3F)
        assert nal_types == [32, 33, 34, 19]

        writer.close()
        await writer.wait_closed()
        await publisher.stop()
        stream.close()
        assert publisher._server is None

    asyncio.run(exercise())


def test_rtp_pcm_is_l16_big_endian_with_metadata_clock():
    async def exercise():
        stream = MediaStream()
        publisher = RtspPublisher("127.0.0.1", 0)
        await publisher.start(stream)
        reader, writer = await asyncio.open_connection("127.0.0.1", publisher.port)
        _, headers, _ = await request(
            reader,
            writer,
            publisher.port,
            "SETUP",
            "/stream/trackID=1",
            1,
            ["Transport: RTP/AVP/TCP;unicast;interleaved=2-3"],
        )
        session = headers["session"].split(";", 1)[0]
        await request(
            reader,
            writer,
            publisher.port,
            "PLAY",
            "/stream",
            2,
            [f"Session: {session}"],
        )
        stream.on_audio(AudioChunk(b"\x34\x12\xfe\xff", 1))
        assert await reader.readexactly(2) == b"$\x02"
        size = struct.unpack(">H", await reader.readexactly(2))[0]
        packet = await reader.readexactly(size)
        assert packet[12:] == b"\x12\x34\xff\xfe"
        writer.close()
        await writer.wait_closed()
        await publisher.stop()
        stream.close()

    asyncio.run(exercise())


@pytest.mark.skipif(
    shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None,
    reason="ffmpeg/ffprobe are unavailable",
)
@pytest.mark.parametrize("transport", ["tcp", "udp"])
def test_ffprobe_reads_published_hevc_stream(transport):
    """Optional real-client integration check with a generated HEVC sample."""

    encoded = subprocess.run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=size=64x64:rate=5",
            "-frames:v",
            "5",
            "-c:v",
            "libx265",
            "-x265-params",
            "pools=1:frame-threads=1:log-level=error",
            "-f",
            "hevc",
            "pipe:1",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    ).stdout

    starts = []
    position = 0
    while position < len(encoded) - 3:
        if encoded[position : position + 4] == b"\x00\x00\x00\x01":
            starts.append((position, 4))
            position += 4
        elif encoded[position : position + 3] == b"\x00\x00\x01":
            starts.append((position, 3))
            position += 3
        else:
            position += 1
    nals = [
        encoded[
            start
            + width : (
                starts[index + 1][0] if index + 1 < len(starts) else len(encoded)
            )
        ]
        for index, (start, width) in enumerate(starts)
    ]
    assert {((nal[0] >> 1) & 0x3F) for nal in nals} >= {32, 33, 34, 20}

    async def exercise():
        stream = MediaStream()
        publisher = RtspPublisher("127.0.0.1", 0)
        await publisher.start(stream)
        process = await asyncio.create_subprocess_exec(
            "ffprobe",
            "-v",
            "error",
            "-rtsp_transport",
            transport,
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=codec_name",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            publisher.url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        deadline = asyncio.get_running_loop().time() + 5
        timestamp = time.monotonic_ns()
        while (
            process.returncode is None and asyncio.get_running_loop().time() < deadline
        ):
            for nal in nals:
                stream.on_video(VideoChunk(ANNEXB_START_CODE + nal, timestamp))
                timestamp += 40_000_000
                await asyncio.sleep(0.01)
            if process.returncode is None:
                await asyncio.sleep(0.05)
        if process.returncode is None:
            process.terminate()
        stdout, stderr = await process.communicate()
        await publisher.stop()
        stream.close()
        assert process.returncode == 0, stderr.decode(errors="replace")
        assert stdout.strip() == b"hevc"

    asyncio.run(exercise())
