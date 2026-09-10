# Testing

The root pytest configuration collects only `tests/`. That directory is the
production and protocol regression suite shipped with the installable project.
All fixtures are synthetic and tests perform no live device or Internet I/O.

## Environment

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run the full production suite:

```sh
python -m pytest -q
```

The KCP behavior suite selects both installed implementations. The `dev` extra
includes CFFI, so an editable install with a compiler builds the native
extension; a `test`-only or base environment exercises the Python fallback.

Run protocol/live-path coverage:

```sh
python -m pytest -q \
  tests/test_lan_framing.py \
  tests/test_lan_protocol_helpers.py \
  tests/test_rtc_signaling.py \
  tests/test_signaling_exchange.py \
  tests/test_udp_protocol.py \
  tests/test_p2p_auth.py \
  tests/test_p2p_channel.py \
  tests/test_p2p_kcp.py \
  tests/test_p2p_mode3.py \
  tests/test_media_playback.py
```

Configuration, resolver, privacy, media, and shutdown behavior are covered by
the remaining files in `tests/`. In particular, activation-delay tests verify
that `--preconnect-activate-delay-ms` defaults to zero and is applied only to
the preconnect activation diagnostic point.

## Suite boundary

The production suite includes:

- configuration models and runtime resolution;
- optional discovery boundaries;
- safe debug redaction;
- LAN 3.3 framing, AES, heartbeat, and decode behavior;
- LAN 3.4 framing, HMAC, session-key negotiation, DPS, and signaling;
- direct candidate interleaving and preconnect activation;
- UDP/STUN parsing, ICE nomination, KCP, Mode 3, and AUTH;
- preview startup records, media parsing/playback, and graceful disconnect.

Byte-level vectors in the production suite are deterministic and
self-contained. They are retained when they encode a stable protocol rule and
contain no private deployment values.

Do not run live-device tests unless the device owner explicitly authorizes
them and supplies configuration outside the repository.
