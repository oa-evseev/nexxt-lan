#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import Counter, deque
from contextlib import ExitStack
from datetime import datetime
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from nexxt.udp_protocol import (
    ClientState,
    EventType,
    handle_udp_datagram,
)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from nexxt.config import (
    ConfigFile,
    load_config,
    resolve_rtc_mode,
    resolve_runtime_config,
    select_camera,
)
from nexxt.device import CameraConfig, ClientConfig, RTCMode
from nexxt import lan33 as lan
from nexxt.lan_framing import LanSignalingTransport
from nexxt.rtc_signaling import (
    ICE_ALPHABET,
    SignalingState,
    build_disconnect_message,
    build_offer,
    build_offer_sdp,
    build_preconnect_activate,
    build_trace_id,
    classify_signaling_message,
    generate_ice_credentials,
    generate_session_aes_key,
    generate_session_id,
    generate_trace_id,
    lifecycle_response_is_accepted,
    local_stun_url,
    make_candidate_message,
    session_number_from_id,
)
from nexxt.media import (
    ANNEXB_START_CODE,
    AudioChunk,
    HevcAssembler,
    MediaPipeline,
    MediaSink,
    MediaStream,
    VideoChunk,
    parse_media_record,
)
from nexxt.rtsp import RtspPublisher, RtspPublisherThread

from tuya_p2p import (
    KCP,
    KCPConfig,
    Mode3Channel,
    Mode3Codec,
    build_auth_info,
)
from tuya_p2p.kcp import KCPBackend, native_available, set_default_backend

# Signaling is event-driven: local ICE candidates are
# trickled while answers and remote candidates are consumed. Keep these
# windows short; they are RX opportunities, not protocol-mandated sleeps.
SIGNALING_OFFER_PUMP_SECONDS = 0.005
SIGNALING_CANDIDATE_PUMP_SECONDS = 0.020
SIGNALING_PUMP_SLICE_SECONDS = 0.050
SIGNALING_ANSWER_TIMEOUT_SECONDS = 2.0

STUN_COOKIE = 0x2112A442
STUN_COOKIE_BYTES = struct.pack(">I", STUN_COOKIE)


# Canonical startup sequence used by both supported live RTC paths.
STARTUP_CONV = 0
PREVIEW_REQUEST_ID = 0x00010004
PREVIEW_CLARITY = 4

LOG = logging.getLogger("nexxt_lan")

REDACTED_VALUE = "<redacted>"
HIGH_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+/-]{11,}={0,2}")
SENSITIVE_INLINE_VALUE_RE = re.compile(
    r"(?P<prefix>(?:a=ice-ufrag:|a=ice-pwd:|a=aes-key:|cname:))"
    r"(?P<value>[^\s\\\",]+)"
)


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy, in bits per character, of ``value``."""
    if not value:
        return 0.0

    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )


def is_high_entropy_token(value: str) -> bool:
    """Identify long token-like values that should not appear in safe logs."""
    if len(value) < 16:
        return False

    entropy = shannon_entropy(value)
    if value.isdigit():
        return entropy >= 2.7
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return entropy >= 2.8
    return entropy >= 3.45


def redact_high_entropy_chunks(value: str) -> str:
    """Redact sensitive SDP fields and high-entropy chunks within a string."""

    def redact_sensitive_field(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{REDACTED_VALUE}"

    value = SENSITIVE_INLINE_VALUE_RE.sub(redact_sensitive_field, value)
    return HIGH_ENTROPY_TOKEN_RE.sub(
        lambda match: (
            REDACTED_VALUE if is_high_entropy_token(match.group(0)) else match.group(0)
        ),
        value,
    )


def redact_high_entropy_json_values(value: object) -> object:
    """Return a copy with sensitive chunks redacted only inside JSON values."""
    if isinstance(value, dict):
        return {
            key: redact_high_entropy_json_values(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_high_entropy_json_values(item) for item in value]
    if isinstance(value, str):
        return redact_high_entropy_chunks(value)
    return value


class DebugFormatter(logging.Formatter):
    """Apply a final redaction pass to debug records unless explicitly unsafe."""

    def __init__(self, *, unsafe_debug: bool) -> None:
        super().__init__("%(message)s")
        self.unsafe_debug = unsafe_debug

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if record.levelno == logging.DEBUG and not self.unsafe_debug:
            return redact_high_entropy_chunks(message)
        return message


def json_for_debug(value: object, *, unsafe_debug: bool) -> str:
    """Format JSON while retaining structure and redacting only its values."""
    output_value = value if unsafe_debug else redact_high_entropy_json_values(value)
    return json.dumps(output_value, indent=2, ensure_ascii=False)


def configure_output(*, debug: bool, debug_unsafe: bool = False) -> None:
    """Configure concise status output with optional protocol diagnostics."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(DebugFormatter(unsafe_debug=debug_unsafe))

    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG if debug or debug_unsafe else logging.INFO)
    LOG.propagate = False


@dataclass(slots=True)
class PreparedSession:
    """Validated data required after generating the signaling offer."""

    local_key: bytes
    offer: dict
    session_id: str
    trace_id: str
    client_id: str
    ice_password: str
    local_ufrag: str
    aes_key: bytes
    auth_plaintext: bytes
    camera: CameraConfig
    # Keep the default at the working camera behavior for programmatic users.
    rtc_mode: RTCMode = RTCMode.DIRECT


class LocalStunServer:
    """Small LAN-only STUN responder for the endpoint advertised in offer."""

    def __init__(self, host: str, port: int, password: str) -> None:
        self._password = password
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((host, port))
        self._socket.settimeout(0.1)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._serve,
            name="local-stun",
            daemon=True,
        )

    def __enter__(self) -> LocalStunServer:
        host, port = self._socket.getsockname()
        LOG.info("[status] Local STUN listening at %s:%d", host, port)
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=0.2)
        self._socket.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                request, addr = self._socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return

            response = stun_success(request, addr, self._password)
            if response is None:
                continue

            try:
                self._socket.sendto(response, addr)
            except OSError:
                return

            LOG.debug(
                "[debug] Local STUN Binding Request peer=%s:%d response=%d",
                addr[0],
                addr[1],
                len(response),
            )


def build_command(request_id: int, cmd1: int, cmd2: int, payload: bytes) -> bytes:
    return (
        struct.pack(
            "<IIIHHI",
            0x12345678,
            request_id,
            0,  # request
            cmd1,
            cmd2,
            len(payload),
        )
        + payload
    )


def build_start_preview(request_id: int, clarity: int) -> bytes:
    payload = struct.pack("<II", 0, clarity)
    return build_command(request_id, 9, 0, payload)


def build_preview_startup(auth_plaintext: bytes) -> list[tuple[str, bytes]]:
    """Build the seven canonical preview-startup messages in order."""
    capability_json = (
        b'{"cmd":"capability_exchange_req","protocol_version":1,'
        b'"data":{"capabilities":{"opus_encode":1,"opus_decode":1}}}\x00'
    )
    sequence = [
        ("AUTH", auth_plaintext),
        ("CMD10", build_command(0, 10, 0, b"\x01\x00\x01\x00")),
        ("CMD21", build_command(0, 21, 0, capability_json)),
        ("CMD2", build_command(2, 2, 0, b"\x00\x00\x00\x00")),
        ("PREVIEW", build_start_preview(PREVIEW_REQUEST_ID, PREVIEW_CLARITY)),
        ("CMD6/0", build_command(0x00010003, 6, 0, struct.pack("<II", 0, 0))),
        ("CMD6/4", build_command(0x00010005, 6, 4, struct.pack("<II", 0, 4))),
    ]
    expected_lengths = (104, 24, 133, 24, 28, 28, 28)
    if tuple(len(plaintext) for _, plaintext in sequence) != expected_lengths:
        raise AssertionError("unexpected preview startup lengths")
    return sequence


def request_preview(channel: Mode3Channel, auth_plaintext: bytes) -> None:
    """Send the canonical preview startup over one conv=0 KCP channel."""
    if channel.kcp.conv != STARTUP_CONV:
        raise ValueError("preview startup requires KCP conv=0")

    credential = auth_plaintext[40:104].split(b"\x00", 1)[0]
    LOG.debug(
        "[startup] AUTH type=1 username=admin credential_sha256=%s",
        hashlib.sha256(credential).hexdigest(),
    )

    for label, plaintext in build_preview_startup(auth_plaintext):
        rc = channel.send(plaintext)
        if rc != 0:
            raise RuntimeError(f"Mode3 {label} send failed: {rc}")

        # Flush each normal KCP send so the seven canonical PUSH segments
        # remain separate UDP payloads.  KCP itself owns their sn values.
        channel.flush()

        if label == "PREVIEW":
            LOG.info(
                "[startup] PREVIEW conv=0 plaintext_len=28 "
                "request_id=0x00010004 clarity=4"
            )
        elif label == "CMD6/0":
            LOG.info(
                "[startup] CMD6/0  conv=0 plaintext_len=28 " "request_id=0x00010003"
            )
        elif label == "CMD6/4":
            LOG.info(
                "[startup] CMD6/4  conv=0 plaintext_len=28 " "request_id=0x00010005"
            )
        else:
            LOG.info("[startup] %-7s conv=0 plaintext_len=%d", label, len(plaintext))


def signaling_timestamp() -> str:
    """Return a wall-clock timestamp for a signaling frame trace."""
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def log_signaling_frame(
    direction: str,
    *,
    seq: int,
    cmd: int,
    payload: bytes,
    key: bytes,
    plaintext: Optional[bytes] = None,
    transport: Optional[LanSignalingTransport] = None,
) -> None:
    """Log the complete, validated Tuya 55AA signaling frame.

    ``recv_frame`` has already checked the prefix, suffix and trailer for RX.
    Rebuilding from its three returned fields produces the identical wire
    bytes without changing socket I/O.  In particular, a negotiated 3.4
    transport must be used here: its trailer is HMAC-SHA256, not CRC32.
    """
    frame = (
        transport.build_frame(seq, cmd, payload)
        if transport is not None
        else lan.build_frame(seq, cmd, payload)
    )
    frame_key = transport.key if transport is not None else key
    prefix, header_seq, header_cmd, length = struct.unpack(">IIII", frame[:16])
    suffix = struct.unpack(">I", frame[-4:])[0]
    trailer_label = "crc"
    trailer_value: Optional[int] = None
    trailer_hmac: Optional[bytes] = None
    if transport is not None and transport.protocol == "3.4":
        trailer_label = "hmac_sha256"
        trailer_hmac = frame[-36:-4]
    else:
        trailer_value = struct.unpack(">I", frame[-8:-4])[0]

    encrypted_payload = payload
    decrypted_payload = (
        plaintext if plaintext is not None else (payload if cmd != 0x20 else None)
    )
    retcode: Optional[int] = None

    if cmd == 0x20 and direction == "RX":
        if len(payload) >= 4:
            retcode = struct.unpack(">I", payload[:4])[0]
            encrypted_payload = payload[4:]
            try:
                decrypted_payload = lan.aes_decrypt(encrypted_payload, frame_key)
            except Exception as exc:
                LOG.debug("[trace] SIGNAL RX decrypt_error=%r", exc)
        else:
            encrypted_payload = b""

    decoded_text: Optional[str] = None
    decoded_json: Optional[object] = None
    if decrypted_payload is not None:
        try:
            decoded_text = decrypted_payload.decode("utf-8")
            try:
                decoded_json = json.loads(decoded_text)
            except json.JSONDecodeError:
                pass
        except UnicodeDecodeError as exc:
            LOG.debug("[trace] SIGNAL %s utf8_decode_error=%r", direction, exc)

    LOG.debug(
        "[trace] SIGNAL %s timestamp=%s seq=%d cmd=0x%08x "
        "wire_len=%d encrypted_payload_len=%d",
        direction,
        signaling_timestamp(),
        seq,
        cmd,
        len(frame),
        len(encrypted_payload),
    )
    LOG.debug(
        "[trace] SIGNAL %s header prefix=0x%08x seq=%d cmd=0x%08x "
        "length=%d %s=%s suffix=0x%08x",
        direction,
        prefix,
        header_seq,
        header_cmd,
        length,
        trailer_label,
        trailer_hmac.hex() if trailer_hmac is not None else f"0x{trailer_value:08x}",
        suffix,
    )
    if retcode is not None:
        LOG.debug("[trace] SIGNAL %s retcode=%d", direction, retcode)
    LOG.debug("[trace] SIGNAL %s frame_hex=%s", direction, frame.hex())
    LOG.debug(
        "[trace] SIGNAL %s encrypted_payload_hex=%s",
        direction,
        encrypted_payload.hex(),
    )
    if decrypted_payload is not None:
        LOG.debug(
            "[trace] SIGNAL %s decrypted_payload_hex=%s",
            direction,
            decrypted_payload.hex(),
        )
    if decoded_json is not None:
        LOG.debug(
            "[trace] SIGNAL %s decoded_json=%s",
            direction,
            json.dumps(decoded_json, ensure_ascii=False, separators=(",", ":")),
        )
    elif decoded_text is not None:
        LOG.debug("[trace] SIGNAL %s decoded_utf8=%s", direction, decoded_text)


def send_json(
    sock: socket.socket,
    seq: int,
    obj: dict,
    key: bytes,
    *,
    transport: Optional[LanSignalingTransport] = None,
    deferred_trace: Optional[
        list[tuple[str, int, int, bytes, bytes, Optional[bytes]]]
    ] = None,
) -> float:
    plain = json.dumps(
        obj,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()

    encrypted = (
        transport.encrypt_signaling(plain) if transport else lan.aes_encrypt(plain, key)
    )
    frame = (
        transport.build_frame(seq, 0x20, encrypted)
        if transport
        else lan.build_frame(seq, 0x20, encrypted)
    )

    # Put the frame on the wire before potentially expensive debug rendering.
    # exchange_signaling() supplies pacing and RX opportunities between frames.
    sock.sendall(frame)
    sent_at = time.monotonic()

    message_type = obj["header"]["type"]
    LOG.info("[request] Signaling %s sent", message_type)
    LOG.debug(
        "[debug] Signaling TX type=%s seq=%d json=%d encrypted=%d",
        message_type,
        seq,
        len(plain),
        len(encrypted),
    )
    if deferred_trace is None:
        log_signaling_frame(
            "TX",
            seq=seq,
            cmd=0x20,
            payload=encrypted,
            key=key,
            plaintext=plain,
            transport=transport,
        )
    else:
        deferred_trace.append(("TX", seq, 0x20, encrypted, key, plain, transport))

    return sent_at


def flush_signaling_traces(
    traces: list[tuple[str, int, int, bytes, bytes, Optional[bytes]]],
) -> None:
    """Render full-frame traces outside the timing-critical exchange path."""
    for trace in traces:
        direction, seq, cmd, payload, key, plaintext, *transport = trace
        log_signaling_frame(
            direction,
            seq=seq,
            cmd=cmd,
            payload=payload,
            key=key,
            plaintext=plaintext,
            transport=transport[0] if transport else None,
        )


def receive_signaling(
    sock: socket.socket,
    key: bytes,
    *,
    seconds: float,
    state: SignalingState,
    camera: Optional[CameraConfig] = None,
    acknowledge_disconnect: bool = False,
    timing_origin: Optional[float] = None,
    deferred_trace: Optional[
        list[tuple[str, int, int, bytes, bytes, Optional[bytes]]]
    ] = None,
    transport: Optional[LanSignalingTransport] = None,
) -> bool:
    deadline = time.monotonic() + seconds

    while time.monotonic() < deadline:
        try:
            seq, cmd, payload = (
                transport.recv_frame(sock) if transport else lan.recv_frame(sock)
            )
        except socket.timeout:
            return False
        except EOFError:
            LOG.warning("[warning] Camera closed the signaling connection")
            return False

        if deferred_trace is None:
            log_signaling_frame(
                "RX",
                seq=seq,
                cmd=cmd,
                payload=payload,
                key=key,
                transport=transport,
            )
        else:
            deferred_trace.append(("RX", seq, cmd, payload, key, None, transport))

        LOG.debug(
            "[debug] Signaling RX seq=%d cmd=0x%02x payload=%d",
            seq,
            cmd,
            len(payload),
        )

        if cmd != 0x20:
            continue

        decoded = (
            transport.decode_camera_payload(payload)
            if transport
            else lan.decode_camera_payload(payload, key)
        )

        if not decoded or "json" not in decoded:
            LOG.warning("[warning] Signaling response could not be decoded")
            continue

        obj = decoded["json"]
        classified = classify_signaling_message(obj)
        if classified is None:
            LOG.warning(
                "[warning] Signaling response has an invalid JSON message shape"
            )
            continue
        typ, hdr, msg = classified

        LOG.debug(
            "[debug] Signaling message type=%s path=%s retcode=%s",
            typ,
            hdr.get("path"),
            decoded.get("retcode"),
        )

        if typ == "answer":
            state.answer_sdp = msg.get("sdp", "")
            LOG.info("[status] Signaling answer received")
            if state.rtc_mode is RTCMode.PRECONNECT:
                LOG.debug("[debug] preconnect answer received")
            if timing_origin is not None:
                LOG.debug(
                    "[debug] signaling timing answer_rx +%.3f ms",
                    (time.monotonic() - timing_origin) * 1000.0,
                )

            for line in state.answer_sdp.splitlines():
                if (
                    line.startswith("m=")
                    or line.startswith("a=rtpmap:")
                    or line.startswith("a=mid:")
                ):
                    LOG.debug("[debug] SDP %s", line)

        elif typ == "candidate":
            candidate = msg.get("candidate", "")
            parts = candidate.split()
            camera_host = None

            if "typ" in parts and "host" in parts and len(parts) >= 6:
                try:
                    ip = parts[4]
                    port = int(parts[5])

                    if camera is not None and ip == camera.ip:
                        camera_host = (ip, port)
                        state.camera_host = camera_host
                except (ValueError, IndexError):
                    pass

            if camera_host:
                LOG.info(
                    "[status] Camera ICE candidate received: %s:%d",
                    *camera_host,
                )
            else:
                LOG.info("[status] ICE candidate received")
            LOG.debug("[debug] Candidate %s", candidate.strip())
            if timing_origin is not None:
                LOG.debug(
                    "[debug] signaling timing remote_candidate_rx +%.3f ms",
                    (time.monotonic() - timing_origin) * 1000.0,
                )

        elif typ == "disconnect":
            if acknowledge_disconnect:
                LOG.info(
                    "[status] Signaling disconnect acknowledged: "
                    "close_reason=%s close_reason_local=%s",
                    msg.get("close_reason"),
                    msg.get("close_reason_local"),
                )
                return True
            LOG.warning(
                "[warning] Camera requested disconnect: remote=%s local=%s",
                msg.get("close_reason"),
                msg.get("close_reason_local"),
            )

    return False


def pump_signaling_until(
    sock: socket.socket,
    key: bytes,
    *,
    deadline: float,
    state: SignalingState,
    camera: Optional[CameraConfig] = None,
    timing_origin: Optional[float] = None,
    stop_when: Optional[Callable[[SignalingState], bool]] = None,
    deferred_trace: Optional[
        list[tuple[str, int, int, bytes, bytes, Optional[bytes]]]
    ] = None,
    transport: Optional[LanSignalingTransport] = None,
) -> bool:
    """Consume signaling in bounded slices until deadline or a condition."""
    previous_timeout = sock.gettimeout()
    try:
        while True:
            if stop_when is not None and stop_when(state):
                return True

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return stop_when(state) if stop_when is not None else False

            receive_window = min(SIGNALING_PUMP_SLICE_SECONDS, remaining)
            sock.settimeout(receive_window)
            receive_signaling(
                sock,
                key,
                seconds=receive_window,
                state=state,
                camera=camera,
                timing_origin=timing_origin,
                deferred_trace=deferred_trace,
                transport=transport,
            )
    finally:
        sock.settimeout(previous_timeout)


def pump_signaling_for(
    sock: socket.socket,
    key: bytes,
    *,
    seconds: float,
    state: SignalingState,
    camera: Optional[CameraConfig] = None,
    started_at: Optional[float] = None,
    timing_origin: Optional[float] = None,
    deferred_trace: Optional[
        list[tuple[str, int, int, bytes, bytes, Optional[bytes]]]
    ] = None,
    transport: Optional[LanSignalingTransport] = None,
) -> None:
    """Provide a short bounded opportunity to process inbound signaling."""
    pump_signaling_until(
        sock,
        key,
        deadline=(time.monotonic() if started_at is None else started_at) + seconds,
        state=state,
        camera=camera,
        timing_origin=timing_origin,
        deferred_trace=deferred_trace,
        transport=transport,
    )


def sdp_attr(sdp: str, name: str) -> Optional[str]:
    prefix = f"a={name}:"

    for line in sdp.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()

    return None


def require_sdp_attr(sdp: str, name: str) -> str:
    value = sdp_attr(sdp, name)

    if value is None:
        raise RuntimeError(f"{name} missing from SDP")

    return value


def stun_attr(attr_type: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4

    return struct.pack(">HH", attr_type, len(value)) + value + b"\x00" * pad


def make_stun_binding_request(
    remote_ufrag: str,
    local_ufrag: str,
    remote_pwd: str,
) -> bytes:
    txid = os.urandom(12)

    priority = stun_attr(
        0x0024,
        struct.pack(">I", 1845501695),
    )

    # Client is ICE-CONTROLLED; camera is ICE-CONTROLLING.
    ice_controlled = stun_attr(
        0x8029,
        os.urandom(8),
    )

    software = stun_attr(
        0x8022,
        b"3.5.5\x00\x00\x00",
    )

    username = stun_attr(
        0x0006,
        f"{remote_ufrag}:{local_ufrag}".encode(),
    )

    body_before_mi = priority + ice_controlled + software + username

    # STUN MESSAGE-INTEGRITY uses a header length ending at MI.
    length_through_mi = len(body_before_mi) + 24

    header_for_mi = struct.pack(
        ">HHI12s",
        0x0001,
        length_through_mi,
        STUN_COOKIE,
        txid,
    )

    digest = hmac.new(
        remote_pwd.encode(),
        header_for_mi + body_before_mi,
        hashlib.sha1,
    ).digest()

    body = body_before_mi + stun_attr(0x0008, digest)

    final_header = struct.pack(
        ">HHI12s",
        0x0001,
        len(body) + 8,
        STUN_COOKIE,
        txid,
    )

    without_fp = final_header + body

    fp = (zlib.crc32(without_fp) & 0xFFFFFFFF) ^ 0x5354554E

    fingerprint = struct.pack(
        ">HHI",
        0x8028,
        4,
        fp,
    )

    return without_fp + fingerprint


def stun_success(
    request: bytes,
    addr: tuple[str, int],
    password: str,
) -> Optional[bytes]:
    if len(request) < 20:
        return None

    msg_type, _msg_len, cookie = struct.unpack(
        ">HHI",
        request[:8],
    )

    if msg_type != 0x0001 or cookie != STUN_COOKIE:
        return None

    txid = request[8:20]

    ip = socket.inet_aton(addr[0])
    port = addr[1]

    xor_port = port ^ (STUN_COOKIE >> 16)
    xor_ip = bytes(a ^ b for a, b in zip(ip, STUN_COOKIE_BYTES))

    xor_mapped = (
        struct.pack(">HH", 0x0020, 8)
        + b"\x00\x01"
        + struct.pack(">H", xor_port)
        + xor_ip
    )

    software_value = b"3.5.5\x00\x00\x00"
    software = struct.pack(">HH", 0x8022, len(software_value)) + software_value

    body_before_mi = xor_mapped + software
    length_through_mi = len(body_before_mi) + 24

    mi_header = struct.pack(
        ">HHI12s",
        0x0101,
        length_through_mi,
        STUN_COOKIE,
        txid,
    )

    digest = hmac.new(
        password.encode(),
        mi_header + body_before_mi,
        hashlib.sha1,
    ).digest()

    body = body_before_mi + struct.pack(">HH", 0x0008, 20) + digest

    final_header = struct.pack(
        ">HHI12s",
        0x0101,
        len(body) + 8,
        STUN_COOKIE,
        txid,
    )

    without_fp = final_header + body

    fp_value = (zlib.crc32(without_fp) & 0xFFFFFFFF) ^ 0x5354554E

    response = without_fp + struct.pack(
        ">HHI",
        0x8028,
        4,
        fp_value,
    )

    # The canonical response layout with this attribute set is 76 bytes.
    assert len(response) == 76, len(response)

    return response


def open_udp_candidate(client: ClientConfig) -> socket.socket:
    udp = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )
    udp.bind((client.local_ip, 0))
    return udp


def send_heartbeat(
    sock: socket.socket,
    *,
    transport: Optional[LanSignalingTransport] = None,
    seq: int = 0,
) -> None:
    # LAN 3.4 sends HEART_BEAT as an empty application payload:
    # only the 55AA header, session-key HMAC-SHA256 and footer are present.
    # 3.3 remains byte-for-byte the legacy empty-payload CRC frame.
    payload = b""
    heartbeat_frame = (
        transport.build_frame(seq, 0x09, payload)
        if transport
        else lan.build_frame(seq, 0x09, payload)
    )
    sock.sendall(heartbeat_frame)

    LOG.info("[request] Heartbeat sent")
    LOG.debug("[debug] Signaling TX heartbeat cmd=0x09")
    log_signaling_frame(
        "TX",
        seq=seq,
        cmd=0x09,
        payload=payload,
        key=transport.key if transport else b"",
        transport=transport,
    )

    try:
        seq, cmd, payload = (
            transport.recv_frame(sock) if transport else lan.recv_frame(sock)
        )

        log_signaling_frame(
            "RX",
            seq=seq,
            cmd=cmd,
            payload=payload,
            key=transport.key if transport else b"",
            transport=transport,
        )

        LOG.info("[status] Heartbeat acknowledged")
        LOG.debug(
            "[debug] Signaling RX heartbeat seq=%d cmd=0x%02x payload=%d",
            seq,
            cmd,
            len(payload),
        )
    except socket.timeout:
        LOG.warning("[warning] Heartbeat was not acknowledged")


def exchange_34_dp_query(
    sock: socket.socket,
    seq: int,
    transport: LanSignalingTransport,
) -> dict:
    """Send the required first post-handshake cmd=0x10 request and read DPS."""
    plaintext = b"{}"
    encrypted = transport.encrypt_payload(0x10, plaintext)
    sock.sendall(transport.build_frame(seq, 0x10, encrypted))
    LOG.info("[request] Tuya 3.4 DPS query sent")
    log_signaling_frame(
        "TX",
        seq=seq,
        cmd=0x10,
        payload=encrypted,
        key=transport.key,
        plaintext=plaintext,
        transport=transport,
    )

    rx_seq, cmd, payload = transport.recv_frame(sock)
    if cmd != 0x10:
        raise RuntimeError(
            f"Tuya 3.4 DPS query failed: expected cmd=0x10, got cmd=0x{cmd:02x}"
        )
    decoded = transport.decode_json_payload(cmd, payload)
    if not decoded or "json" not in decoded:
        detail = decoded.get("decode_error") if decoded else "empty response"
        raise RuntimeError(
            f"Tuya 3.4 DPS query response could not be decoded: {detail}"
        )

    response_plaintext = json.dumps(
        decoded["json"],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    log_signaling_frame(
        "RX",
        seq=rx_seq,
        cmd=cmd,
        payload=payload,
        key=transport.key,
        plaintext=response_plaintext,
        transport=transport,
    )
    LOG.info("[status] Tuya 3.4 DPS query acknowledged")
    return decoded


def receive_lifecycle_response(
    sock: socket.socket,
    transport: LanSignalingTransport,
    *,
    expected_type: str,
    expected_cmd: int = 0x20,
    expected_handle: Optional[int] = None,
    expected_seq: Optional[int] = None,
    max_frames: int = 8,
) -> bool:
    """Wait for a lifecycle JSON response, allowing its preceding transport ACK.

    LAN 3.4 may emit a zero-retcode, four-byte ``cmd=0x20`` ACK before an
    application JSON replies.  It is not the application reply, so retain the
    same socket and sequence context and keep reading a bounded number of
    frames.  A direct JSON response remains valid too.
    """
    expected_fields = {"activate_resp": (1, 1)}
    if expected_type in expected_fields:
        default_handle, default_seq = expected_fields[expected_type]
        expected_handle = default_handle if expected_handle is None else expected_handle
        expected_seq = default_seq if expected_seq is None else expected_seq

    for frame_number in range(1, max_frames + 1):
        try:
            rx_seq, cmd, payload = transport.recv_frame(sock)
        except socket.timeout:
            LOG.warning(
                "[warning] RTC lifecycle %s response was not received", expected_type
            )
            return False
        except EOFError:
            LOG.warning(
                "[warning] Camera closed during RTC lifecycle %s", expected_type
            )
            return False

        log_signaling_frame(
            "RX",
            seq=rx_seq,
            cmd=cmd,
            payload=payload,
            key=transport.key,
            transport=transport,
        )
        if cmd != expected_cmd:
            LOG.debug(
                "[debug] RTC lifecycle waiting for %s: ignoring cmd=0x%02x frame=%d",
                expected_type,
                cmd,
                frame_number,
            )
            continue

        # The preliminary ACK is exactly four bytes: a big-endian
        # retcode with no encrypted payload following it.
        if len(payload) == 4:
            retcode = struct.unpack(">I", payload)[0]
            if retcode != 0:
                LOG.warning(
                    "[warning] RTC lifecycle %s transport ACK failed: retcode=%d",
                    expected_type,
                    retcode,
                )
                return False
            LOG.info(
                "[status] RTC lifecycle %s transport ACK retcode=0; awaiting JSON response",
                expected_type,
            )
            continue

        decoded = transport.decode_json_payload(cmd, payload)
        if not decoded or "json" not in decoded:
            LOG.warning(
                "[warning] RTC lifecycle %s received undecodable signaling frame=%d; continuing",
                expected_type,
                frame_number,
            )
            continue

        plain = json.dumps(
            decoded["json"], separators=(",", ":"), ensure_ascii=False
        ).encode()
        # Render a decoded payload in the trace in addition to the generic raw
        # frame trace above; this preserves the protocol-header-aware decode.
        log_signaling_frame(
            "RX",
            seq=rx_seq,
            cmd=cmd,
            payload=payload,
            key=transport.key,
            plaintext=plain,
            transport=transport,
        )
        obj = decoded["json"]
        hdr = obj.get("header", {})
        msg = obj.get("msg", {})
        response_type = hdr.get("type")
        LOG.info(
            "[status] RTC lifecycle response type=%s handle=%s error=%s seq=%s",
            response_type,
            msg.get("handle"),
            msg.get("error"),
            msg.get("seq"),
        )
        if response_type != expected_type:
            LOG.debug(
                "[debug] RTC lifecycle waiting for %s: received %s; continuing",
                expected_type,
                response_type,
            )
            continue
        if expected_handle is not None and msg.get("handle") != expected_handle:
            LOG.warning(
                "[warning] RTC lifecycle %s handle=%s, expected %s",
                expected_type,
                msg.get("handle"),
                expected_handle,
            )
            return False
        if expected_seq is not None and msg.get("seq") != expected_seq:
            LOG.warning(
                "[warning] RTC lifecycle %s seq=%s, expected %s",
                expected_type,
                msg.get("seq"),
                expected_seq,
            )
            return False
        if expected_type == "activate_resp" and msg.get("error") != 0:
            LOG.warning(
                "[warning] RTC lifecycle %s reported error=%s",
                expected_type,
                msg.get("error"),
            )
            return False
        return lifecycle_response_is_accepted(
            obj,
            expected_type=expected_type,
            expected_handle=expected_handle,
            expected_seq=expected_seq,
        )

    LOG.warning(
        "[warning] RTC lifecycle %s was not received in %d frames",
        expected_type,
        max_frames,
    )
    return False


def activate_preconnect_session(
    sock: socket.socket,
    session: PreparedSession,
    signaling: SignalingState,
    *,
    activate_delay_ms: int = 0,
) -> None:
    """Activate an ICE-prepared preconnect session before preview commands."""
    if session.rtc_mode is not RTCMode.PRECONNECT:
        raise RuntimeError("preconnect activation requires preconnect RTC mode")
    transport = signaling.transport
    if transport is None or transport.protocol != "3.4":
        raise RuntimeError("preconnect activation requires Tuya LAN 3.4 signaling")

    activate = build_preconnect_activate(session)
    LOG.debug(
        "[debug] diagnostic preconnect activate delay applied: %d ms",
        activate_delay_ms,
    )
    if activate_delay_ms:
        time.sleep(activate_delay_ms / 1000)
    LOG.debug("[debug] preconnect activate sent")
    send_json(
        sock,
        signaling.next_seq,
        activate,
        session.local_key,
        transport=transport,
    )
    signaling.next_seq += 1
    if not receive_lifecycle_response(
        sock,
        transport,
        expected_type="activate_resp",
        expected_handle=1,
        expected_seq=1,
    ):
        raise RuntimeError("preconnect activate_resp was not accepted")
    LOG.debug("[debug] preconnect activate_resp accepted")


def send_initial_ice_check(
    udp: socket.socket,
    signaling: SignalingState,
    *,
    local_ufrag: str,
) -> None:
    if not signaling.camera_host:
        LOG.warning("[warning] ICE check skipped: camera candidate is missing")
        return

    if not signaling.answer_sdp:
        LOG.warning("[warning] ICE check skipped: answer SDP is missing")
        return

    remote_ufrag = sdp_attr(
        signaling.answer_sdp,
        "ice-ufrag",
    )
    remote_pwd = sdp_attr(
        signaling.answer_sdp,
        "ice-pwd",
    )

    if not remote_ufrag or not remote_pwd:
        LOG.warning("[warning] ICE check skipped: answer credentials are missing")
        return

    request = make_stun_binding_request(
        remote_ufrag,
        local_ufrag,
        remote_pwd,
    )

    udp.sendto(
        request,
        signaling.camera_host,
    )

    LOG.info("[request] ICE connectivity check sent")
    LOG.debug(
        "[debug] STUN Binding Request TX peer=%s:%d bytes=%d",
        signaling.camera_host[0],
        signaling.camera_host[1],
        len(request),
    )


def now_ms() -> int:
    return int(time.monotonic() * 1000) & 0xFFFFFFFF


MEDIA_CONVS = (1, 2)
MEDIA_KCP_CONFIG = KCPConfig(
    mtu=1400,
    snd_wnd=32,
    rcv_wnd=128,
    nodelay=0,
    interval=20,
    resend=10,
    nc=1,
)


class PlaybackPipe:
    """Lazy ffplay subprocess with a bounded, non-network writer thread.

    ``offer`` never waits for the child process.  The default overflow policy is
    appropriate for PCM: discard the oldest chunk, keeping playback close to
    real time.  HEVC uses ``codec_safe=True``; see ``_offer_video_locked``.
    """

    def __init__(
        self,
        *,
        label: str,
        command: list[str],
        max_chunks: Optional[int] = None,
        max_bytes: Optional[int] = None,
        codec_safe: bool = False,
        process_factory=subprocess.Popen,
    ) -> None:
        self.label = label
        self.dropped = 0
        self.dropped_bytes = 0
        self.queue_peak_chunks = 0
        self.queue_peak_bytes = 0
        self.overflow_events = 0
        self.decoder_resyncs = 0
        self._accepting = True
        self._broken = False
        self._command = command
        self._process_factory = process_factory
        # Keep max_chunks for small test sinks, while real players use bytes.
        self._max_chunks = max_chunks
        self._max_bytes = max_bytes if max_bytes is not None else 4 * 1024 * 1024
        self._codec_safe = codec_safe
        self._desynchronised = False
        self._parameter_sets: dict[int, bytes] = {}
        self._queue: deque[bytes] = deque()
        self._queued_bytes = 0
        self._condition = threading.Condition()
        self.process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _nal_type(chunk: bytes) -> Optional[int]:
        if len(chunk) < len(ANNEXB_START_CODE) + 1:
            return None
        offset = len(ANNEXB_START_CODE) if chunk.startswith(ANNEXB_START_CODE) else 0
        if len(chunk) <= offset:
            return None
        return (chunk[offset] >> 1) & 0x3F

    def _start_locked(self) -> bool:
        if self.process is not None:
            return True
        try:
            self.process = self._process_factory(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                bufsize=0,
            )
        except OSError as exc:
            self._mark_dead_locked(f"could not start: {exc}")
            return False
        self._thread = threading.Thread(
            target=self._writer,
            name=f"nexxt-{self.label}-writer",
            daemon=True,
        )
        self._thread.start()
        LOG.info("[status] %s live playback started", self.label)
        return True

    def _mark_dead_locked(self, reason: object) -> None:
        if not self._broken:
            self._broken = True
            LOG.info("[status] %s playback closed: %s", self.label, reason)
        self._queue.clear()
        self._queued_bytes = 0
        self._condition.notify_all()

    def _fits_locked(self, chunk: bytes) -> bool:
        return (
            len(chunk) <= self._max_bytes
            and self._queued_bytes + len(chunk) <= self._max_bytes
            and (self._max_chunks is None or len(self._queue) < self._max_chunks)
        )

    def _append_locked(self, chunk: bytes) -> None:
        self._queue.append(chunk)
        self._queued_bytes += len(chunk)
        self.queue_peak_chunks = max(self.queue_peak_chunks, len(self._queue))
        self.queue_peak_bytes = max(self.queue_peak_bytes, self._queued_bytes)
        self._condition.notify()

    def _drop_locked(self, chunk: bytes) -> None:
        self.dropped += 1
        self.dropped_bytes += len(chunk)

    def _offer_video_locked(self, chunk: bytes) -> None:
        nal_type = self._nal_type(chunk)
        if nal_type in (32, 33, 34):
            self._parameter_sets[nal_type] = chunk

        if self._desynchronised:
            # A parameter set is retained above, but nothing is fed until a
            # random-access picture makes a new decoder state possible.
            if nal_type not in (19, 20, 21):
                if nal_type not in (32, 33, 34):
                    self._drop_locked(chunk)
                return
            restart = [
                self._parameter_sets[k]
                for k in (32, 33, 34)
                if k in self._parameter_sets
            ] + [chunk]
            if any(len(part) > self._max_bytes for part in restart) or (
                sum(map(len, restart)) > self._max_bytes
            ):
                # An individual giant access point cannot be safely buffered.
                for part in restart:
                    self._drop_locked(part)
                return
            for part in restart:
                self._append_locked(part)
            self._desynchronised = False
            self.decoder_resyncs += 1
            return

        if self._fits_locked(chunk):
            self._append_locked(chunk)
            return

        # Do not remove just one inter-predicted NAL.  Flush pending input and
        # wait for an IRAP, carrying the latest VPS/SPS/PPS to that boundary.
        self.overflow_events += 1
        while self._queue:
            self._drop_locked(self._queue.popleft())
        self._queued_bytes = 0
        self._desynchronised = True
        self._offer_video_locked(chunk)

    def offer(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._condition:
            if not self._accepting or self._broken:
                return
            if not self._start_locked():
                return
            if self._codec_safe:
                self._offer_video_locked(chunk)
                return
            # PCM is independently decodable; evict old audio on sustained
            # backpressure instead of blocking the KCP receive loop.
            while not self._fits_locked(chunk) and self._queue:
                discarded = self._queue.popleft()
                self._queued_bytes -= len(discarded)
                self._drop_locked(discarded)
            if not self._fits_locked(chunk):
                self.overflow_events += 1
                self._drop_locked(chunk)
                return
            self._append_locked(chunk)

    def _writer(self) -> None:
        try:
            while True:
                with self._condition:
                    while not self._queue and self._accepting and not self._broken:
                        self._condition.wait()
                    if not self._queue:
                        return
                    chunk = self._queue.popleft()
                    self._queued_bytes -= len(chunk)
                process = self.process
                if process is None or process.stdin is None:
                    raise BrokenPipeError("ffplay stdin is unavailable")
                remaining = memoryview(chunk)
                while remaining:
                    written = process.stdin.write(remaining)
                    if not written:
                        raise BrokenPipeError("ffplay stdin accepted zero bytes")
                    remaining = remaining[written:]
                process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            with self._condition:
                self._mark_dead_locked(exc)
        finally:
            process = self.process
            try:
                if process is not None and process.stdin is not None:
                    process.stdin.close()
            except (BrokenPipeError, OSError):
                pass

    def close(self) -> None:
        with self._condition:
            self._accepting = False
            # Shutdown loss is not a runtime overflow diagnostic.
            self._queue.clear()
            self._queued_bytes = 0
            self._condition.notify_all()
        thread = self._thread
        process = self.process
        if thread is None or process is None:
            return
        thread.join(timeout=1.0)
        if thread.is_alive() and process.poll() is None:
            process.terminate()
            thread.join(timeout=1.0)

        try:
            process.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
        thread.join(timeout=0.5)


class DumpMediaSink:
    def __init__(self, directory: Path) -> None:
        self._video = (directory / "video.h265").open("wb")
        self._audio = (directory / "audio.s16le").open("wb")

    def start(self) -> None:
        pass

    def on_video(self, chunk: VideoChunk) -> None:
        self._video.write(chunk.data)
        self._video.flush()

    def on_audio(self, chunk: AudioChunk) -> None:
        self._audio.write(chunk.data)
        self._audio.flush()

    def close(self) -> None:
        self._video.close()
        self._audio.close()


class PlaybackMediaSink:
    def __init__(self, ffplay_path: str) -> None:
        self.video_pipe = PlaybackPipe(
            label="HEVC",
            command=[
                ffplay_path,
                "-loglevel",
                "warning",
                "-fflags",
                "nobuffer",
                "-flags",
                "low_delay",
                "-framedrop",
                "-f",
                "hevc",
                "-",
            ],
            max_bytes=16 * 1024 * 1024,
            codec_safe=True,
        )
        self.audio_pipe = PlaybackPipe(
            label="PCM audio",
            command=[
                ffplay_path,
                "-loglevel",
                "warning",
                "-nodisp",
                "-fflags",
                "nobuffer",
                "-f",
                "s16le",
                "-ar",
                "8000",
                "-ch_layout",
                "mono",
                "-",
            ],
            max_bytes=128 * 1024,
        )

    def start(self) -> None:
        pass

    def on_video(self, chunk: VideoChunk) -> None:
        self.video_pipe.offer(chunk.data)

    def on_audio(self, chunk: AudioChunk) -> None:
        self.audio_pipe.offer(chunk.data)

    def close(self) -> None:
        self.video_pipe.close()
        self.audio_pipe.close()


class MediaLogSink:
    def __init__(self) -> None:
        self._video_started = False
        self._audio_started = False

    def start(self) -> None:
        pass

    def on_video(self, chunk: VideoChunk) -> None:
        if not self._video_started:
            LOG.info("[media] HEVC first NAL type=%d", chunk.nal_type)
            self._video_started = True

    def on_audio(self, chunk: AudioChunk) -> None:
        if not self._audio_started:
            LOG.info("[media] PCM audio started: s16le 8000 Hz mono")
            self._audio_started = True

    def close(self) -> None:
        pass


class MediaOutput:
    """Compatibility facade around the backend-neutral composable pipeline."""

    def __init__(
        self,
        *,
        play: bool,
        ffplay_path: Optional[str],
        dump_dir: Optional[Path],
        sinks: tuple[MediaSink, ...] | list[MediaSink] = (),
    ) -> None:
        configured_sinks = [MediaLogSink(), *sinks]
        if dump_dir is not None:
            configured_sinks.append(DumpMediaSink(dump_dir))
        self._playback: Optional[PlaybackMediaSink] = None
        if play:
            if ffplay_path is None:
                raise RuntimeError("--play requires ffplay in PATH")
            self._playback = PlaybackMediaSink(ffplay_path)
            configured_sinks.append(self._playback)
        self.pipeline = MediaPipeline(configured_sinks)
        self.video_pipe = self._playback.video_pipe if self._playback else None
        self.audio_pipe = self._playback.audio_pipe if self._playback else None

    @property
    def assembler(self) -> HevcAssembler:
        return self.pipeline.assembler

    @property
    def video_chunks(self) -> int:
        return self.pipeline.video_chunks

    @property
    def audio_chunks(self) -> int:
        return self.pipeline.audio_chunks

    @property
    def audio_bytes(self) -> int:
        return self.pipeline.audio_bytes

    @property
    def bad_records(self) -> Counter[int]:
        return self.pipeline.bad_records

    def feed(self, conv: int, message_index: int, message: bytes) -> None:
        self.pipeline.feed_record(conv, message_index, message)

    def close(self) -> None:
        self.pipeline.close()

    def summary(self) -> None:
        video_dropped = self.video_pipe.dropped if self.video_pipe is not None else 0
        audio_dropped = self.audio_pipe.dropped if self.audio_pipe is not None else 0
        LOG.info(
            "[media] video complete_nals=%d reassembled_fu=%d dropped=%d "
            "anomalies=%d bad_records=%d queue_peak_chunks=%d "
            "queue_peak_bytes=%d overflow_events=%d decoder_resyncs=%d",
            self.assembler.complete_nals,
            self.assembler.reassembled_fu,
            video_dropped,
            self.assembler.anomalies,
            self.bad_records[1],
            self.video_pipe.queue_peak_chunks if self.video_pipe else 0,
            self.video_pipe.queue_peak_bytes if self.video_pipe else 0,
            self.video_pipe.overflow_events if self.video_pipe else 0,
            self.video_pipe.decoder_resyncs if self.video_pipe else 0,
        )
        LOG.info(
            "[media] audio chunks=%d bytes=%d dropped=%d bad_records=%d "
            "queue_peak_chunks=%d queue_peak_bytes=%d overflow_events=%d",
            self.audio_chunks,
            self.audio_bytes,
            audio_dropped,
            self.bad_records[2],
            self.audio_pipe.queue_peak_chunks if self.audio_pipe else 0,
            self.audio_pipe.queue_peak_bytes if self.audio_pipe else 0,
            self.audio_pipe.overflow_events if self.audio_pipe else 0,
        )


def printable_bytes(data: bytes, limit: int = 64) -> str:
    """Render a bounded byte prefix without putting binary data in the log."""
    return "".join(
        chr(byte) if 32 <= byte < 127 else f"\\x{byte:02x}" for byte in data[:limit]
    )


@dataclass
class MediaStats:
    conv: int
    crypto_records: int = 0
    decrypt_failures: int = 0
    messages: int = 0
    total_bytes: int = 0
    min_length: Optional[int] = None
    max_length: int = 0
    lengths: Counter[int] = field(default_factory=Counter)
    first_at: Optional[float] = None
    last_at: Optional[float] = None
    annexb_messages: int = 0
    annexb_start_codes: int = 0
    push_packets: int = 0
    ack_packets: int = 0
    first_gap: Optional[tuple[int, int]] = None

    def record(self, message: bytes) -> int:
        timestamp = time.monotonic()
        index = self.messages
        self.messages += 1
        length = len(message)
        self.total_bytes += length
        self.min_length = (
            length if self.min_length is None else min(self.min_length, length)
        )
        self.max_length = max(self.max_length, length)
        self.lengths[length] += 1
        if self.first_at is None:
            self.first_at = timestamp
        self.last_at = timestamp
        return index


class MediaReceiver:
    """One signed, raw-payload KCP receiver for a camera media conversation."""

    def __init__(
        self,
        *,
        conv: int,
        key: bytes,
        output,
        dump_dir: Optional[Path],
        on_message: Optional[Callable[[int, int, bytes], None]] = None,
    ) -> None:
        self.conv = conv
        self.codec = Mode3Codec(key)
        self.stats = MediaStats(conv=conv)
        self._output = output
        self._on_message = on_message
        self.kcp = KCP(conv, self._kcp_output, config=MEDIA_KCP_CONFIG)
        self._bin = None
        self._messages = None
        self._encrypted = None
        if dump_dir is not None:
            self._bin = (dump_dir / f"conv{conv}.bin").open("wb")
            self._messages = (dump_dir / f"conv{conv}.messages").open("wb")
            # Failed records are framed so their original KCP-message
            # boundaries remain available for offline crypto investigation.
            self._encrypted = (dump_dir / f"conv{conv}.encrypted").open("wb")

        LOG.info(
            "[media] conv=%d KCP receiver initialized rcv_nxt=%d "
            "rcv_wnd=%d interval=%d",
            conv,
            self.kcp.rcv_nxt,
            self.kcp.rcv_wnd,
            self.kcp.interval,
        )

    def close(self) -> None:
        for handle in (self._bin, self._messages, self._encrypted):
            if handle is not None:
                handle.close()

    def _kcp_output(self, datagram: bytes) -> None:
        """KCP emits ACK/WINS packets; sign and put them on the ICE path."""
        ack_count = 0
        offset = 0
        while len(datagram) - offset >= 24:
            _, cmd, _, _, _, _, _, length = struct.unpack_from(
                "<IBBHIIII", datagram, offset
            )
            offset += 24 + length
            if cmd == 0x52:  # IKCP_CMD_ACK
                ack_count += 1
        self.stats.ack_packets += ack_count
        if ack_count:
            LOG.debug(
                "[debug] media KCP ACK TX conv=%d segments=%d bytes=%d",
                self.conv,
                ack_count,
                len(datagram),
            )
        self._output(self.codec.sign(datagram))

    def input(self, kcp_datagram: bytes, packet) -> int:
        """Feed one already verified/stripped KCP datagram."""
        if packet.cmd == 0x51:
            self.stats.push_packets += 1
            expected = self.kcp.rcv_nxt
            if packet.sn != expected and self.stats.first_gap is None:
                self.stats.first_gap = (expected, packet.sn)
                LOG.debug(
                    "[debug] media KCP conv=%d first out-of-order/gap "
                    "expected_sn=%d received_sn=%d",
                    self.conv,
                    expected,
                    packet.sn,
                )
        return self.kcp.input(kcp_datagram)

    def drain(self) -> None:
        while (encrypted_message := self.kcp.recv()) is not None:
            # KCP preserves one crypto record per recv().  Never concatenate
            # records: every record has its own IV and PKCS#7 padding.
            index = self.stats.crypto_records
            self.stats.crypto_records += 1
            try:
                message = self.codec.decrypt(encrypted_message)
            except ValueError as exc:
                self.stats.decrypt_failures += 1
                LOG.warning(
                    "[warning] media decrypt failed conv=%d msg=%d "
                    "ciphertext_len=%d iv=%s: %s",
                    self.conv,
                    index,
                    max(0, len(encrypted_message) - 16),
                    encrypted_message[:16].hex(),
                    exc,
                )
                if self._encrypted is not None:
                    self._encrypted.write(struct.pack("<I", len(encrypted_message)))
                    self._encrypted.write(encrypted_message)
                    self._encrypted.flush()
                continue

            self.stats.record(message)
            prefix = message[:64]
            LOG.debug(
                "[media] conv=%d msg=%d len=%d prefix=%s",
                self.conv,
                index,
                len(message),
                prefix.hex(),
            )
            if index < 20:
                LOG.debug(
                    "[media] conv=%d msg=%d ascii=%s",
                    self.conv,
                    index,
                    printable_bytes(message),
                )

            stripped = message.lstrip()
            if stripped.startswith((b"{", b"[")):
                LOG.debug(
                    "[media] conv=%d msg=%d signature=JSON-like", self.conv, index
                )
            elif prefix and all(
                32 <= byte < 127 for byte in prefix[: min(8, len(prefix))]
            ):
                LOG.debug(
                    "[media] conv=%d msg=%d signature=ASCII-magic value=%s",
                    self.conv,
                    index,
                    printable_bytes(prefix, 16),
                )
            elif len(prefix) >= 8:
                LOG.debug(
                    "[debug] media conv=%d msg=%d signature=binary-header prefix=%s",
                    self.conv,
                    index,
                    prefix[:16].hex(),
                )

            start_offsets = []
            pos = 0
            while True:
                four = message.find(b"\\x00\\x00\\x00\\x01", pos)
                three = message.find(b"\\x00\\x00\\x01", pos)
                candidates = [item for item in (four, three) if item >= 0]
                if not candidates:
                    break
                offset = min(candidates)
                start_offsets.append(offset)
                pos = offset + (4 if offset == four else 3)
            if start_offsets:
                self.stats.annexb_messages += 1
                self.stats.annexb_start_codes += len(start_offsets)
                LOG.debug(
                    "[media] conv=%d msg=%d annexb-start-code offset=%d",
                    self.conv,
                    index,
                    start_offsets[0],
                )

            if self._bin is not None:
                self._bin.write(message)
                self._messages.write(struct.pack("<I", len(message)))
                self._messages.write(message)
                self._bin.flush()
                self._messages.flush()
            if self._on_message is not None:
                self._on_message(self.conv, index, message)

    def update(self, timestamp_ms: int) -> None:
        self.kcp.update(timestamp_ms)

    def summary(self) -> None:
        stats = self.stats
        duration = (
            (stats.last_at - stats.first_at)
            if stats.first_at is not None and stats.last_at is not None
            else 0.0
        )
        rate = stats.total_bytes / duration if duration > 0 else 0.0
        common = (
            ",".join(
                f"{length}x{count}" for length, count in stats.lengths.most_common(5)
            )
            or "-"
        )
        LOG.info(
            "[media] conv=%d records=%d decrypt_failures=%d messages=%d "
            "bytes=%d min=%d max=%d annexb=%d "
            "start_codes=%d bytes_per_sec=%.1f first_at=%s last_at=%s "
            "common_lengths=%s",
            stats.conv,
            stats.crypto_records,
            stats.decrypt_failures,
            stats.messages,
            stats.total_bytes,
            stats.min_length or 0,
            stats.max_length,
            stats.annexb_messages,
            stats.annexb_start_codes,
            rate,
            f"{stats.first_at:.6f}" if stats.first_at is not None else "-",
            f"{stats.last_at:.6f}" if stats.last_at is not None else "-",
            common,
        )
        LOG.info(
            "[media] conv=%d KCP PUSH fed=%d ACK generated=%d rcv_nxt=%d "
            "rcv_queue=%d rcv_buf=%d%s",
            stats.conv,
            stats.push_packets,
            stats.ack_packets,
            self.kcp.rcv_nxt,
            len(self.kcp.rcv_queue),
            len(self.kcp.rcv_buf),
            (
                f" first_gap_expected={stats.first_gap[0]}"
                f"_received={stats.first_gap[1]}"
                if stats.first_gap is not None
                else ""
            ),
        )


def run_udp_loop(
    udps: list[socket.socket],
    *,
    ice_pwd: str,
    auth_plaintext: bytes,
    aes_key: bytes,
    dump_media: Optional[Path] = None,
    play: bool = False,
    ffplay_path: Optional[str] = None,
    media_sinks: tuple[MediaSink, ...] | list[MediaSink] = (),
    on_prepared: Optional[Callable[[], None]] = None,
) -> None:
    LOG.info("[status] Waiting for ICE nomination " "(preview startup is not sent yet)")

    for udp in udps:
        udp.setblocking(False)

    startup_sent = False
    udp_state = ClientState()

    peer_addr: Optional[tuple[str, int]] = None
    peer_udp: Optional[socket.socket] = None

    def make_mode3_output(label: str, channel_conv: int):
        def output(datagram: bytes) -> None:
            if peer_addr is None:
                raise RuntimeError("Mode3 output before ICE peer was selected")

            if peer_udp is None:
                raise RuntimeError("Mode3 output before ICE socket was selected")

            peer_udp.sendto(datagram, peer_addr)

            LOG.debug(
                "[debug] MODE3 %s TX peer=%s:%d bytes=%d conv=0x%08x",
                label,
                peer_addr[0],
                peer_addr[1],
                len(datagram),
                channel_conv,
            )

        return output

    startup_channel = Mode3Channel(
        key=aes_key,
        conv=STARTUP_CONV,
        output=make_mode3_output(
            "STARTUP",
            STARTUP_CONV,
        ),
        kcp_config=KCPConfig(
            mtu=1400,
            snd_wnd=32,
            rcv_wnd=128,
            # Canonical KCP parameters for the supported device profiles.
            nodelay=0,
            interval=20,
            resend=10,
            nc=1,
        ),
    )

    if dump_media is not None:
        dump_media.mkdir(parents=True, exist_ok=True)
        LOG.info("[media] Writing reassembled media dumps to %s", dump_media)

    media_output = MediaOutput(
        play=play,
        ffplay_path=ffplay_path,
        dump_dir=dump_media,
        sinks=media_sinks,
    )

    media_receivers = {
        conv: MediaReceiver(
            conv=conv,
            key=aes_key,
            output=make_mode3_output("MEDIA ACK", conv),
            dump_dir=dump_media,
            on_message=media_output.feed,
        )
        for conv in MEDIA_CONVS
    }
    wire_codec = Mode3Codec(aes_key)

    try:
        while True:
            now = now_ms()
            startup_channel.update(now)
            for receiver in media_receivers.values():
                receiver.update(now)

            ready, _, _ = select.select(udps, [], [], 0.05)
            if not ready:
                continue

            udp = ready[0]
            try:
                data, addr = udp.recvfrom(65535)
            except BlockingIOError:
                continue

            LOG.debug(
                "[debug] UDP RX peer=%s:%d bytes=%d prefix=%s",
                addr[0],
                addr[1],
                len(data),
                data[:8].hex(),
            )

            event = handle_udp_datagram(
                data,
                addr,
                udp_state,
            )

            if event.type == EventType.INVALID:
                LOG.warning(
                    "[warning] Invalid UDP datagram from %s:%d: %s",
                    addr[0],
                    addr[1],
                    event.reason,
                )
                continue

            if event.type == EventType.BINDING_SUCCESS:
                LOG.debug(
                    "[debug] STUN Binding Success peer=%s:%d bytes=%d txid=%s",
                    addr[0],
                    addr[1],
                    len(data),
                    event.txid.hex(),
                )
                continue

            if event.type == EventType.BINDING_REQUEST:
                response = stun_success(
                    data,
                    addr,
                    ice_pwd,
                )

                if response:
                    udp.sendto(
                        response,
                        addr,
                    )

                LOG.debug(
                    "[debug] STUN Binding Request #%d peer=%s:%d bytes=%d "
                    "txid=%s use_candidate=%s response=%d",
                    udp_state.seen_binding_requests,
                    addr[0],
                    addr[1],
                    len(data),
                    event.txid.hex(),
                    event.use_candidate,
                    len(response) if response else 0,
                )

                if event.use_candidate and not startup_sent:
                    peer_addr = addr
                    peer_udp = udp
                    LOG.info(
                        "[status] ICE candidate nominated: %s:%d",
                        addr[0],
                        addr[1],
                    )

                    startup_channel.update(now_ms())
                    if on_prepared is not None:
                        LOG.debug("[debug] preconnect prepared session ready")
                        on_prepared()
                    request_preview(startup_channel, auth_plaintext)
                    startup_sent = True
                    LOG.info("[request] Preview startup sent")

                continue

            if event.type == EventType.STUN_ERROR:
                LOG.warning(
                    "[warning] STUN error from %s:%d: code=%s",
                    addr[0],
                    addr[1],
                    event.error_code,
                )
                LOG.debug("[debug] STUN error txid=%s", event.txid.hex())
                continue

            if event.type == EventType.OTHER_STUN:
                LOG.debug(
                    "[debug] Other STUN peer=%s:%d type=0x%04x bytes=%d txid=%s",
                    addr[0],
                    addr[1],
                    event.stun_type,
                    len(data),
                    event.txid.hex(),
                )
                continue

            if event.type == EventType.KCP:
                kcp = event.kcp
                assert kcp is not None

                # The KCP parser above only establishes the wire shape.  Do
                # not trust its conv or feed any KCP state until the shared
                # mode-3 HMAC trailer has been verified and removed.
                try:
                    verified_kcp_datagram = wire_codec.verify(data)
                except ValueError as exc:
                    LOG.warning(
                        "[warning] KCP integrity check failed from %s:%d: %s",
                        addr[0],
                        addr[1],
                        exc,
                    )
                    continue

                LOG.debug(
                    "[debug] KCP RX peer=%s:%d conv=0x%08x cmd=0x%02x "
                    "frg=%d wnd=%d ts=%d sn=%d una=%d payload=%d trailer=%d",
                    addr[0],
                    addr[1],
                    kcp.conv,
                    kcp.cmd,
                    kcp.frg,
                    kcp.wnd,
                    kcp.ts,
                    kcp.sn,
                    kcp.una,
                    len(kcp.payload),
                    len(kcp.trailer),
                )

                if kcp.conv == STARTUP_CONV:
                    try:
                        rc = startup_channel.input(data)
                    except ValueError as exc:
                        LOG.warning(
                            "[warning] MODE3 STARTUP response rejected: %s",
                            exc,
                        )
                        continue

                    if rc < 0:
                        LOG.warning(
                            "[warning] MODE3 STARTUP KCP input failed: %d",
                            rc,
                        )
                        continue

                    startup_channel.update(now_ms())

                    while True:
                        message = startup_channel.recv()

                        if message is None:
                            break

                        LOG.info(
                            "[status] MODE3 STARTUP response received (%d bytes)",
                            len(message),
                        )
                        LOG.debug(
                            "[debug] MODE3 STARTUP response hex=%s",
                            message.hex(),
                        )

                elif kcp.conv in media_receivers:
                    receiver = media_receivers[kcp.conv]
                    try:
                        rc = receiver.input(verified_kcp_datagram, kcp)
                    except ValueError as exc:
                        LOG.warning(
                            "[warning] media KCP conv=%d rejected: %s",
                            kcp.conv,
                            exc,
                        )
                        continue

                    if rc < 0:
                        LOG.warning(
                            "[warning] media KCP conv=%d input failed: %d",
                            kcp.conv,
                            rc,
                        )
                        continue

                    # KCP queues ACKs during input; update()/flush() is what
                    # actually puts those ACKs on the nominated ICE socket.
                    receiver.update(now_ms())
                    receiver.drain()

            if event.type == EventType.NON_STUN:
                LOG.debug(
                    "[debug] Non-STUN UDP peer=%s:%d bytes=%d prefix=%s",
                    addr[0],
                    addr[1],
                    len(event.payload),
                    event.payload[:32].hex(),
                )

    except KeyboardInterrupt:
        # The caller still owns live signaling and session resources, so it
        # can perform the graceful-disconnect sequence first.
        raise
    finally:
        media_output.close()
        for receiver in media_receivers.values():
            receiver.summary()
            receiver.close()
        media_output.summary()


def prepare_session(
    *,
    client: ClientConfig,
    camera: CameraConfig,
    debug: bool,
    debug_unsafe: bool = False,
    rtc_mode: RTCMode = RTCMode.DIRECT,
) -> PreparedSession:
    """Build and validate the offer plus the credentials derived from it."""
    if rtc_mode is RTCMode.PRECONNECT and camera.lan_protocol != "3.4":
        raise RuntimeError("preconnect RTC mode requires a Tuya LAN 3.4 camera")
    local_key_text = camera.local_key
    local_key = local_key_text.encode()
    # Each connection attempt gets a fresh local credential set.
    ice_credentials = generate_ice_credentials()
    session_aes_key = generate_session_aes_key()
    dev_id = camera.device_id
    session_id = generate_session_id(dev_id)
    base_trace_id = generate_trace_id()
    trace_id = build_trace_id(base_trace_id=base_trace_id, dev_id=camera.device_id)
    offer = build_offer(
        client,
        camera,
        session_id=session_id,
        trace_id=trace_id,
        ice_credentials=ice_credentials,
        aes_key=session_aes_key,
        rtc_mode=rtc_mode,
    )

    LOG.info("[status] Signaling offer prepared")
    LOG.debug(
        "[debug] Generated local ICE credentials: ufrag=%s password_length=%d",
        ice_credentials[0],
        len(ice_credentials[1]),
    )
    LOG.debug(
        "[debug] Generated local session ID=%s sdp_session_number=%d",
        session_id,
        session_number_from_id(session_id, camera.device_id),
    )
    LOG.debug(
        "[debug] Generated base trace ID=%s wire trace_id=%s",
        base_trace_id,
        trace_id,
    )
    LOG.debug(
        "[debug] Offer JSON:\n%s",
        json_for_debug(offer, unsafe_debug=debug_unsafe),
    )

    header = offer["header"]
    generated_sdp = offer["msg"]["sdp"]
    aes_key = bytes.fromhex(require_sdp_attr(generated_sdp, "aes-key"))
    if len(aes_key) != 16:
        raise RuntimeError(f"unexpected aes-key length: {len(aes_key)}")
    if aes_key != session_aes_key:
        raise RuntimeError("generated SDP AES key mismatch")

    auth_plaintext = build_auth_info(
        camera.password,
        local_key_text,
        auth_type=1,
    )
    if len(auth_plaintext) != 104:
        raise RuntimeError(f"unexpected auth plaintext length: {len(auth_plaintext)}")

    return PreparedSession(
        local_key=local_key,
        offer=offer,
        session_id=header["sessionid"],
        trace_id=trace_id,
        client_id=header["from"],
        ice_password=require_sdp_attr(generated_sdp, "ice-pwd"),
        local_ufrag=require_sdp_attr(generated_sdp, "ice-ufrag"),
        aes_key=aes_key,
        auth_plaintext=auth_plaintext,
        camera=camera,
        rtc_mode=rtc_mode,
    )


def build_local_candidate(
    session: PreparedSession,
    client: ClientConfig,
    udp: socket.socket,
) -> dict:
    """Create and describe the local ICE candidate bound to ``udp``."""
    udp_port = udp.getsockname()[1]
    candidate = make_candidate_message(
        client_id=session.client_id,
        device_id=session.camera.device_id,
        session_id=session.session_id,
        trace_id=session.trace_id,
        local_ip=client.local_ip,
        local_port=udp_port,
    )

    LOG.info("[status] Local ICE candidate ready: %s:%d", client.local_ip, udp_port)
    LOG.debug("[debug] Session id=%s", session.session_id)
    LOG.debug("[debug] Preview startup channel conv=0x%08x", STARTUP_CONV)
    return candidate


def open_signaling_connection(camera: CameraConfig) -> socket.socket:
    LOG.info(
        "[status] Connecting to camera signaling at %s:%d",
        camera.ip,
        camera.signaling_port,
    )
    sock = socket.create_connection((camera.ip, camera.signaling_port), timeout=5)
    sock.settimeout(3)
    LOG.info("[status] Signaling connection established")
    return sock


def exchange_signaling(
    sock: socket.socket,
    session: PreparedSession,
    candidates: list[dict],
    camera: Optional[CameraConfig] = None,
    *,
    state: Optional[SignalingState] = None,
) -> SignalingState:
    """Send offer plus local candidates, then collect the camera's response."""
    camera = camera or getattr(session, "camera", None)
    signaling = state if state is not None else SignalingState()
    rtc_mode = getattr(session, "rtc_mode", RTCMode.DIRECT)
    signaling.rtc_mode = rtc_mode
    deferred_traces: list[tuple[str, int, int, bytes, bytes, Optional[bytes]]] = []
    transport = LanSignalingTransport(
        camera.lan_protocol if camera is not None else "3.3",
        session.local_key,
    )
    signaling.transport = transport
    transport_kwargs = {"transport": transport} if transport.protocol == "3.4" else {}
    if transport.protocol == "3.4":
        signaling.next_seq = transport.negotiate_session_key(
            sock,
            signaling.next_seq,
        )
        exchange_34_dp_query(sock, signaling.next_seq, transport)
        signaling.next_seq += 1
        send_heartbeat(sock, transport=transport, seq=signaling.next_seq)
        signaling.next_seq += 1
    else:
        # Keep the former 3.3 invocation and wire path untouched.
        send_heartbeat(sock)
    offer_tx = send_json(
        sock,
        signaling.next_seq,
        session.offer,
        session.local_key,
        **transport_kwargs,
        deferred_trace=deferred_traces,
    )
    if rtc_mode is RTCMode.PRECONNECT:
        LOG.debug("[debug] preconnect offer sent")
    timing_origin = offer_tx
    answer_deadline = offer_tx + SIGNALING_ANSWER_TIMEOUT_SECONDS
    LOG.debug("[debug] signaling timing offer_tx +0.000 ms")
    signaling.next_seq += 1
    signaling.session_started = True

    # Preserve event-driven candidate interleaving: briefly pump after the offer,
    # then consume answer/remote candidates between local transmissions.
    pump_signaling_for(
        sock,
        session.local_key,
        seconds=SIGNALING_OFFER_PUMP_SECONDS,
        state=signaling,
        camera=camera,
        started_at=offer_tx,
        timing_origin=timing_origin,
        deferred_trace=deferred_traces,
        **transport_kwargs,
    )
    for candidate_index, candidate in enumerate(candidates, start=1):
        candidate_tx = send_json(
            sock,
            signaling.next_seq,
            candidate,
            session.local_key,
            deferred_trace=deferred_traces,
            **transport_kwargs,
        )
        LOG.debug(
            "[debug] signaling timing candidate_tx index=%d +%.3f ms",
            candidate_index,
            (candidate_tx - timing_origin) * 1000.0,
        )
        signaling.next_seq += 1
        pump_signaling_for(
            sock,
            session.local_key,
            seconds=SIGNALING_CANDIDATE_PUMP_SECONDS,
            state=signaling,
            camera=camera,
            started_at=candidate_tx,
            timing_origin=timing_origin,
            deferred_trace=deferred_traces,
            **transport_kwargs,
        )

    # Retain the original two-second overall answer budget without one
    # monolithic blocking recv after a burst of outbound candidates.
    pump_signaling_until(
        sock,
        session.local_key,
        deadline=answer_deadline,
        state=signaling,
        camera=camera,
        timing_origin=timing_origin,
        deferred_trace=deferred_traces,
        **transport_kwargs,
        stop_when=lambda current: bool(
            current.answer_sdp and current.camera_host is not None
        ),
    )
    flush_signaling_traces(deferred_traces)

    if not signaling.answer_sdp:
        raise RuntimeError("signaling answer not received")

    if signaling.camera_host is None:
        raise RuntimeError("camera host candidate not received")

    if rtc_mode is RTCMode.PRECONNECT:
        LOG.debug("[debug] preconnect candidates complete")

    return signaling


def graceful_disconnect(
    sock: socket.socket,
    session: PreparedSession,
    signaling: SignalingState,
) -> None:
    """Send exactly one best-effort client disconnect before close."""
    if not signaling.session_started or signaling.disconnect_sent:
        return

    # Mark before I/O: a second Ctrl+C or another finally path must never
    # create a duplicate disconnect frame.
    signaling.disconnect_sent = True
    try:
        send_json(
            sock,
            signaling.next_seq,
            build_disconnect_message(session),
            session.local_key,
            transport=signaling.transport,
        )
        signaling.next_seq += 1

        # Shutdown must not wait on the ordinary three-second signaling
        # timeout. The reply is useful diagnostics only, never a condition
        # for resource cleanup.
        previous_timeout = sock.gettimeout()
        try:
            sock.settimeout(0.25)
            receive_signaling(
                sock,
                session.local_key,
                seconds=0.3,
                state=signaling,
                camera=session.camera,
                acknowledge_disconnect=True,
                transport=signaling.transport,
            )
        finally:
            sock.settimeout(previous_timeout)
    except KeyboardInterrupt:
        LOG.info("[status] Shutdown interrupted; continuing resource cleanup")
    except Exception as exc:
        # Do not turn a best-effort shutdown failure into the primary failure.
        LOG.debug("[debug] Signaling disconnect cleanup failed: %r", exc)


def run_lan_preview(
    *,
    client: ClientConfig,
    camera: CameraConfig,
    debug: bool,
    debug_unsafe: bool = False,
    dump_media: Optional[Path] = None,
    play: bool = False,
    rtc_mode: RTCMode = RTCMode.DIRECT,
    preconnect_activate_delay_ms: int = 0,
    rtsp_listen: Optional[tuple[str, int]] = None,
) -> None:
    """Run the complete LAN signaling, ICE and encrypted preview workflow."""
    debug_enabled = debug or debug_unsafe
    configure_output(debug=debug_enabled, debug_unsafe=debug_unsafe)
    LOG.info(
        "[status] Selected camera %s (%s) at %s:%d",
        camera.name,
        camera.device_id,
        camera.ip,
        camera.signaling_port,
    )
    ffplay_path = shutil.which("ffplay") if play else None
    if play and ffplay_path is None:
        raise RuntimeError("--play requires ffplay in PATH")
    media_stream: Optional[MediaStream] = None
    rtsp_thread: Optional[RtspPublisherThread] = None
    if rtsp_listen is not None:
        media_stream = MediaStream()
        rtsp_thread = RtspPublisherThread(RtspPublisher(*rtsp_listen))
        url = rtsp_thread.start(media_stream)
        LOG.info("[status] RTSP stream available at %s", url)

    try:
        session = prepare_session(
            client=client,
            camera=camera,
            debug=debug_enabled,
            debug_unsafe=debug_unsafe,
            rtc_mode=rtc_mode,
        )

        # The offer advertises this endpoint as its only STUN server.  Keep the
        # responder alive for the entire signaling/ICE exchange, so that the
        # advertised LAN endpoint is real rather than merely descriptive JSON.
        with ExitStack() as stack:
            primary_udp = stack.enter_context(open_udp_candidate(client))
            udp_sockets = [primary_udp, stack.enter_context(open_udp_candidate(client))]
            stack.enter_context(
                LocalStunServer(client.local_ip, client.stun_port, session.ice_password)
            )
            candidates = [
                build_local_candidate(session, client, udp) for udp in udp_sockets
            ]

            with open_signaling_connection(camera) as sock:
                signaling = SignalingState()
                try:
                    exchange_signaling(
                        sock,
                        session,
                        candidates,
                        camera,
                        state=signaling,
                    )
                    send_initial_ice_check(
                        primary_udp,
                        signaling,
                        local_ufrag=session.local_ufrag,
                    )
                    LOG.debug(
                        "[debug] Auth plaintext prepared bytes=%d hex=%s",
                        len(session.auth_plaintext),
                        session.auth_plaintext.hex(),
                    )
                    udp_kwargs: dict[str, Callable[[], None]] = {}
                    if session.rtc_mode is RTCMode.PRECONNECT:
                        udp_kwargs["on_prepared"] = lambda: activate_preconnect_session(
                            sock,
                            session,
                            signaling,
                            activate_delay_ms=preconnect_activate_delay_ms,
                        )
                    run_udp_loop(
                        udp_sockets,
                        ice_pwd=session.ice_password,
                        auth_plaintext=session.auth_plaintext,
                        aes_key=session.aes_key,
                        dump_media=dump_media,
                        play=play,
                        ffplay_path=ffplay_path,
                        media_sinks=[media_stream] if media_stream is not None else [],
                        **udp_kwargs,
                    )
                except KeyboardInterrupt:
                    # Ctrl+C is an ordinary request to end an active LAN session.
                    # The finally block runs while this TCP socket is still open.
                    LOG.info("[status] Graceful shutdown requested")
                finally:
                    graceful_disconnect(sock, session, signaling)
    finally:
        if media_stream is not None:
            media_stream.close()
        if rtsp_thread is not None:
            rtsp_thread.stop()


def non_negative_integer(value: str) -> int:
    """Parse a non-negative integer for diagnostic CLI controls."""
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def parse_rtsp_listen(value: str) -> tuple[str, int]:
    """Parse HOST:PORT, including bracketed IPv6 literals."""
    host, separator, port_text = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("must be HOST:PORT")
    host = host.strip("[]")
    try:
        port = int(port_text, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("RTSP port must be an integer") from exc
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("RTSP port must be between 0 and 65535")
    return host, port


def apply_kcp_backend(backend: KCPBackend) -> None:
    """Apply the CLI's process-wide KCP selection before session setup."""
    if backend == "native" and not native_available():
        raise RuntimeError(
            "--kcp-backend native was requested, but the native KCP backend is "
            "unavailable; install nexxt-lan[native] with a supported native build"
        )
    set_default_backend(backend)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command-line options without starting the LAN workflow."""
    parser = argparse.ArgumentParser(
        description="Connect to a Nexxt camera through the LAN P2P workflow."
    )
    debug_options = parser.add_mutually_exclusive_group()
    debug_options.add_argument(
        "--debug",
        action="store_true",
        help="show technical diagnostics with sensitive tokens redacted",
    )
    debug_options.add_argument(
        "--debug-unsafe",
        action="store_true",
        help="show unredacted technical diagnostics (may expose secrets)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="path to a version 1 config stored outside the installed package",
    )
    parser.add_argument(
        "--camera",
        required=True,
        help="configured camera name (or device ID)",
    )
    parser.add_argument(
        "--rtc-mode",
        choices=[mode.value for mode in RTCMode],
        default=None,
        help="override the configured RTC startup mode (diagnostic use only)",
    )
    parser.add_argument(
        "--kcp-backend",
        choices=("auto", "native", "python"),
        default="auto",
        help="KCP implementation for this process (default: auto)",
    )
    parser.add_argument(
        "--preconnect-activate-delay-ms",
        type=non_negative_integer,
        default=0,
        metavar="MS",
        help=(
            "diagnostic delay after ICE nomination and before preconnect "
            "activate (default: 0)"
        ),
    )
    parser.add_argument(
        "--dump-media",
        type=Path,
        metavar="DIR",
        help=(
            "write sensitive decrypted media plaintext to DIR/conv{1,2}.bin and "
            "length-framed DIR/conv{1,2}.messages; failed encrypted "
            "records are length-framed in DIR/conv{1,2}.encrypted"
        ),
    )
    parser.add_argument(
        "--play",
        action="store_true",
        help="play live HEVC video and s16le 8 kHz mono audio with ffplay",
    )
    parser.add_argument(
        "--rtsp-listen",
        type=parse_rtsp_listen,
        metavar="HOST:PORT",
        help="publish HEVC and PCM as RTSP (for example 127.0.0.1:8554)",
    )
    args = parser.parse_args(argv)
    if args.play and shutil.which("ffplay") is None:
        parser.error("--play requires ffplay in PATH")
    return args


def main() -> None:
    args = parse_args()
    try:
        apply_kcp_backend(args.kcp_backend)
        config = load_config(args.config)
        client, camera = resolve_runtime_config(config, args.camera)
        rtc_mode = resolve_rtc_mode(camera, args.rtc_mode)
        run_lan_preview(
            client=client,
            camera=camera,
            debug=args.debug,
            debug_unsafe=args.debug_unsafe,
            dump_media=args.dump_media,
            play=args.play,
            rtc_mode=rtc_mode,
            preconnect_activate_delay_ms=args.preconnect_activate_delay_ms,
            rtsp_listen=args.rtsp_listen,
        )
    except KeyboardInterrupt:
        # This also covers a repeated Ctrl+C while context managers are
        # releasing resources.  The session-level cleanup itself is already
        # idempotent and has marked its disconnect as sent.
        LOG.info("[status] Shutdown complete")
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
