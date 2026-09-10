# nexxt-lan

`nexxt-lan` is an installable Python LAN client for two verified Nexxt/Tuya
camera workflows:

- LAN 3.3 with `rtc_mode: "direct"`
- LAN 3.4 with `rtc_mode: "preconnect"`

It performs RTC signaling, ICE/STUN nomination, KCP/Mode 3 transport, AUTH,
preview startup, media parsing, optional playback, and graceful disconnect.

## Installation

Python 3.10 or newer is required. The default installation needs no C
compiler: it uses the portable pure-Python KCP implementation when the
optional native extension is absent.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

For the preferred CFFI binding of upstream KCP, install the native extra. It
pulls the separately published, platform-specific `nexxt-lan-native`
distribution, which declares CFFI as its own isolated build dependency:

```sh
python -m pip install 'nexxt-lan[native]'
```

When building both unpublished distributions from a checkout, build the
native wheel first and offer it to pip as a local artifact:

```sh
python -m pip wheel --wheel-dir dist ./native
python -m pip install --find-links dist '.[native]'
```

Install optional TinyTuya discovery support with:

```sh
python -m pip install '.[discovery]'
```

## KCP backend selection

KCP uses the native implementation when it is installed and otherwise falls
back to Python. Integration tests or an embedding application can explicitly
select the backend for subsequently created implicit KCP instances:

```python
from tuya_p2p.kcp import set_default_backend, using_backend

set_default_backend("python")  # process-wide; pass "auto" to reset

with using_backend("native"):
    ...  # restored even if the enclosed operation raises
```

An explicit `KCP(..., backend="python")` always overrides this default.
The CLI exposes the same process-wide choice as
`--kcp-backend auto|native|python`; for example, append `--kcp-backend python`
to run the complete client without the native extension.

`ffplay` is an optional external executable. It is needed only for `--play`
and is not installed as a Python dependency.

RTSP publishing is built in and adds no external executable or Python
dependency. The focused RTSP 1.0 server supports the playback operations used
by ffmpeg/ffplay, VLC and go2rtc, with RTP either interleaved over TCP or over
unicast UDP. This avoids requiring a separate gateway such as MediaMTX for a
single camera while leaving the media API usable by one later.

## Configuration

The application never searches for configuration beside installed source.
Every invocation must provide an explicit external file with `--config PATH`.
Copy `config.example.json` to a private location, replace its synthetic
profiles, and set the environment variables named by that file.

```sh
cp config.example.json /path/to/private/nexxt-config.json
nexxt-lan --config /path/to/private/nexxt-config.json \
  --camera example-direct-camera
```

The config contains non-secret device profiles plus names of environment
variables. Device keys and passwords remain in the environment. A local
`config.json` and `.env*` are ignored and must not be committed.

Each enabled camera declares `lan_protocol`, `rtc_mode`, signaling port, and
environment-variable names for its current IP, local key, and password. The
client section declares environment-variable names for client ID, bind IP,
and STUN port. See `config.example.json` for the version 1 schema.

For the foreground multi-camera runner, opt a profile in by adding
`"rtsp_path": "laundry"`.  Alternatively, `"rtsp": true` opts it in and
uses the camera name as its path. Profiles without either setting are never
published by `serve`, even if they are enabled. Paths are one URL-safe segment.

TinyTuya discovery is optional and imported only when its resolver is used.
The configured environment resolver remains the default CLI behavior.

## Supported operation

Run a configured live profile:

```sh
nexxt-lan --config /path/to/private/nexxt-config.json --camera PROFILE
```

`--rtc-mode` can override the configured mode for diagnostics, but only the
two combinations listed above are supported. The LAN 3.4 preconnect path
requires ICE nomination before activation.

Useful diagnostics are explicit opt-ins:

- `--debug` emits structured technical logs with sensitive tokens redacted.
- `--preconnect-activate-delay-ms MS` delays activation after nomination.
  Its default is `0`; it is diagnostic and is not protocol policy.
- `--play` sends HEVC video and 8 kHz mono signed 16-bit PCM audio to
  `ffplay`.
- `--dump-media DIR` writes decrypted media and failed encrypted records.
- `--rtsp-listen HOST:PORT` publishes the live stream at
  `rtsp://HOST:PORT/stream`. For local-only access, use
  `--rtsp-listen 127.0.0.1:8554`; to expose it on the LAN, bind the intended
  interface address explicitly.
- `--debug-unsafe` enables unredacted tracing.

To publish multiple opt-in profiles through one listener, use the `serve`
subcommand. With no `--camera` it publishes all RTSP-enabled profiles; each
repeatable `--camera NAME` restricts that set (and does not opt an otherwise
private profile in):

```sh
nexxt-lan serve --config /path/to/private/nexxt-config.json \
  --camera example-direct-camera --camera example-preconnect-camera \
  --rtsp-listen 127.0.0.1:8554
```

Each `serve` camera reserves its own OS-assigned local STUN port before its
offer is generated. That port is advertised only in that camera's STUN URL;
the configured `stun_port_env` remains the fixed-port behavior for the legacy
single-camera command.

`--debug-unsafe` and `--dump-media` can disclose credentials, identifiers,
session material, network details, audio, and video. Use private output
locations and remove the results when no longer needed.

## Media API and RTSP lifecycle

The reusable boundary lives in `nexxt.media`. `MediaPipeline.feed_record()` is
the only adapter from decrypted Nexxt records. It emits `VideoChunk` objects
containing one complete HEVC Annex-B NAL and `AudioChunk` objects containing
PCM s16le samples with 8000 Hz, mono and two-byte sample metadata. Synchronous
`MediaSink` callbacks keep the existing receive loop simple; `MediaStream`
turns those callbacks into a thread-safe broadcast whose subscriptions are
async iterators.

The RTSP API is independent of camera transport. One `RtspServer` owns one
listen socket and can publish multiple independent `MediaStream` instances:

```python
from nexxt import MediaStream, RtspServer

server = RtspServer("127.0.0.1", 8554)
await server.start()

laundry_url = await server.publish("laundry", laundry_stream)
feeder_url = await server.publish("cat-feeder", feeder_stream)
# Attach each stream as a sink to its camera's MediaPipeline.
...
await server.unpublish("laundry")
await server.stop()
```

Publication paths are normalized to one URL-safe segment (`laundry` becomes
`/laundry`); duplicates are rejected. The existing `RtspPublisher` remains as
a one-path compatibility wrapper for the CLI. Client disconnects only release
that client's RTP state. Shutdown closes the media pipeline, performs the
existing graceful camera disconnect and stops RTSP.

The publisher caches the latest VPS, SPS and PPS. A newly playing client is
held until the next HEVC IRAP NAL, then receives the cached parameter sets and
that random-access NAL before subsequent media. HEVC is never decoded or
re-encoded. PCM byte order is changed losslessly from little endian to the
network-order L16 RTP representation.

## Testing

```sh
python -m pip install '.[test]'
python -m pytest -q
```

For formatter tooling, install `.[dev]`. The production suite is synthetic,
deterministic, and requires no real camera or network. See
`docs/TESTING.md` for focused commands and suite boundaries.

## Known limitations

- The network implementation is IPv4-oriented.
- WAN/TURN/TCP fallback and a complete ICE engine are not implemented.
- RTSP is an unauthenticated single-process publisher intended for trusted LAN
  use. It does not implement recording, multicast or RTCP quality feedback.
- Camera records currently expose NAL rather than full access-unit timing, so
  video RTP timestamps use monotonic arrival time and assume the common camera
  case where a VCL NAL ends a picture. This should be validated per additional
  camera model before broad Home Assistant packaging.
- Incoming STUN validation and multi-segment KCP datagram classification remain
  limited.
- AUTH type semantics, complete response schemas, session reuse, and several
  native error mappings remain unresolved.
- Preconnect readiness can exhibit a timing-sensitive `error=-25`. The
  `--preconnect-activate-delay-ms` default remains `0`; no fixed delay is a
  confirmed protocol requirement.
