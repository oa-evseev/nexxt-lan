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
- `--debug-unsafe` enables unredacted tracing.

`--debug-unsafe` and `--dump-media` can disclose credentials, identifiers,
session material, network details, audio, and video. Use private output
locations and remove the results when no longer needed.

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
- Incoming STUN validation and multi-segment KCP datagram classification remain
  limited.
- AUTH type semantics, complete response schemas, session reuse, and several
  native error mappings remain unresolved.
- Preconnect readiness can exhibit a timing-sensitive `error=-25`. The
  `--preconnect-activate-delay-ms` default remains `0`; no fixed delay is a
  confirmed protocol requirement.
