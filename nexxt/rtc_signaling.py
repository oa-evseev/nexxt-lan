"""RTC signaling JSON construction and signaling-local state.

This module deliberately sits between LAN framing and the preview
orchestration.  It knows RTC JSON identities and message shapes, but never
opens sockets, frames LAN commands, runs ICE, or makes lifecycle timing
decisions.
"""

from __future__ import annotations

import secrets
import string
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Protocol

from nexxt.device import CameraConfig, ClientConfig, RTCMode
from nexxt.lan_framing import LanSignalingTransport

ICE_ALPHABET = string.ascii_letters + string.digits


@dataclass(slots=True)
class SignalingState:
    """State accumulated by signaling exchange, not ICE or media state."""

    answer_sdp: str = ""
    camera_host: Optional[tuple[str, int]] = None
    next_seq: int = 1
    session_started: bool = False
    disconnect_sent: bool = False
    transport: Optional[LanSignalingTransport] = None
    rtc_mode: RTCMode = RTCMode.DIRECT


class PreparedSignalingSession(Protocol):
    """The identity portion of an orchestration-owned prepared session."""

    session_id: str
    trace_id: str
    client_id: str
    camera: CameraConfig


def generate_ice_credentials() -> tuple[str, str]:
    return (
        "".join(secrets.choice(ICE_ALPHABET) for _ in range(4)),
        "".join(secrets.choice(ICE_ALPHABET) for _ in range(24)),
    )


def generate_session_aes_key() -> bytes:
    return secrets.token_bytes(16)


def generate_session_id(dev_id: str) -> str:
    suffix = "".join(secrets.choice(ICE_ALPHABET) for _ in range(8))
    return f"{dev_id}{int(time.time() * 1000)}{suffix}"


def generate_trace_id() -> str:
    return str(uuid.uuid4())


def local_stun_url(client: ClientConfig) -> str:
    host = client.local_ip
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"stun:{host}:{client.stun_port}"


def session_number_from_id(session_id: str, dev_id: str) -> int:
    if not session_id.startswith(dev_id):
        raise RuntimeError(f"unexpected sessionId: {session_id!r}")
    digits = []
    for ch in session_id[len(dev_id) :]:
        if not ch.isdigit():
            break
        digits.append(ch)
    if not digits:
        raise RuntimeError(f"cannot extract SDP session number from {session_id!r}")
    return int("".join(digits))


def build_offer_sdp(
    *, session: dict, session_id: str, ice_credentials: tuple[str, str], aes_key: bytes
) -> str:
    dev_id, uid = session["devId"], session["uid"]
    ice_ufrag, ice_pwd = ice_credentials
    if not isinstance(aes_key, bytes) or len(aes_key) != 16:
        raise RuntimeError("local session AES key must be 16 raw bytes")
    number = session_number_from_id(session_id, dev_id)
    lines = [
        "v=0",
        f"o=- {number} 1 IN IP4 127.0.0.1",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE imm0",
        f"a=msid-semantic: WMS {session_id}",
        "m=application 9 imm 6001",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        f"a=ice-ufrag:{ice_ufrag}",
        f"a=ice-pwd:{ice_pwd}",
        "a=ice-options:trickle",
        f"a=aes-key:{aes_key.hex()}",
        "a=mid:imm0",
        "a=rtpmap:6001 AES/KCP 330",
        f"a=ssrc:0 cname:{uid}",
    ]
    return "\r\n".join(lines) + "\r\n"


def build_trace_id(*, base_trace_id: str, dev_id: str) -> str:
    return f"{base_trace_id}_{dev_id}_{int(time.time() * 1000)}"


def build_offer(
    client: ClientConfig,
    camera: CameraConfig,
    *,
    session_id: str,
    trace_id: str,
    ice_credentials: tuple[str, str],
    aes_key: bytes,
    rtc_mode: RTCMode = RTCMode.DIRECT,
) -> dict:
    msg = {
        "sdp": build_offer_sdp(
            session={"devId": camera.device_id, "uid": client.uid},
            session_id=session_id,
            ice_credentials=ice_credentials,
            aes_key=aes_key,
        ),
        "token": [{"urls": local_stun_url(client)}],
    }
    header = {
        "from": client.uid,
        "path": "lan",
        "sessionid": session_id,
        "to": camera.device_id,
        "trace_id": trace_id,
        "type": "offer",
    }
    if rtc_mode is RTCMode.PRECONNECT:
        header.update({"is_pre": 1, "p2p_skill": 1635, "security_level": 3})
        msg["preconnect"] = True
    return {"header": header, "msg": msg}


def make_candidate_message(
    *,
    client_id: str,
    device_id: str,
    session_id: str,
    trace_id: str,
    local_ip: str,
    local_port: int,
    foundation: Optional[int] = None,
) -> dict:
    if foundation is None:
        foundation = secrets.randbelow(2**31)
    return {
        "header": {
            "from": client_id,
            "moto_id": "",
            "path": "lan",
            "sessionid": session_id,
            "to": device_id,
            "trace_id": trace_id,
            "type": "candidate",
        },
        "msg": {
            "candidate": f"a=candidate:1 1 UDP 2130706431 {local_ip} {local_port} typ host\r\n"
        },
    }


def _lifecycle_header(
    session: PreparedSignalingSession,
    message_type: str,
    *,
    include_sub_dev_id: bool = False,
) -> dict:
    header = {
        "from": session.client_id,
        "moto_id": "",
        "path": "lan",
        "sessionid": session.session_id,
    }
    if include_sub_dev_id:
        header["sub_dev_id"] = ""
    header.update(
        {
            "to": session.camera.device_id,
            "trace_id": session.trace_id,
            "type": message_type,
        }
    )
    return header


def build_disconnect_message(session: PreparedSignalingSession) -> dict:
    return {
        "header": _lifecycle_header(session, "disconnect", include_sub_dev_id=True),
        "msg": {"close_reason": 5, "close_reason_local": 0},
    }


def build_preconnect_activate(session: PreparedSignalingSession) -> dict:
    return {
        "header": _lifecycle_header(session, "activate"),
        "msg": {"handle": 1, "seq": 1},
    }


def classify_signaling_message(obj: object) -> Optional[tuple[str, dict, dict]]:
    """Return ``(type, header, msg)`` for a structurally valid signaling JSON."""
    if not isinstance(obj, dict):
        return None
    header, msg = obj.get("header"), obj.get("msg")
    if not isinstance(header, dict) or not isinstance(msg, dict):
        return None
    message_type = header.get("type")
    return (message_type, header, msg) if isinstance(message_type, str) else None


def lifecycle_response_is_accepted(
    obj: object,
    *,
    expected_type: str,
    expected_handle: Optional[int] = None,
    expected_seq: Optional[int] = None,
) -> bool:
    """Apply the existing lifecycle JSON type/handle/seq/error policy only."""
    classified = classify_signaling_message(obj)
    if classified is None:
        return False
    response_type, _header, msg = classified
    if response_type != expected_type:
        return False
    defaults = {"activate_resp": (1, 1)}
    if response_type in defaults:
        handle, seq = defaults[response_type]
        expected_handle = handle if expected_handle is None else expected_handle
        expected_seq = seq if expected_seq is None else expected_seq
    if expected_handle is not None and msg.get("handle") != expected_handle:
        return False
    if expected_seq is not None and msg.get("seq") != expected_seq:
        return False
    return not (expected_type == "activate_resp" and msg.get("error") != 0)
