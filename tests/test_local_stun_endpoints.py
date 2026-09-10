import socket
import struct

import nexxt_lan
from nexxt.device import CameraConfig, ClientConfig

CLIENT = ClientConfig("client", "127.0.0.1", 3478)
CAMERA = CameraConfig("camera", "device", "192.0.2.3", 6668, "0123456789abcdef", "pw")


def binding_request(transaction: bytes) -> bytes:
    return struct.pack(">HHI12s", 0x0001, 0, nexxt_lan.STUN_COOKIE, transaction)


def request_response(server, request):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 0))
        peer.settimeout(1)
        peer.sendto(request, ("127.0.0.1", server.port))
        response, _address = peer.recvfrom(65535)
        return response, peer.getsockname()


def test_two_session_stun_endpoints_use_distinct_ports_and_passwords():
    first, first_client = nexxt_lan.open_local_stun_endpoint(CLIENT, port=0)
    second, second_client = nexxt_lan.open_local_stun_endpoint(CLIENT, port=0)
    request = binding_request(b"x" * 12)
    try:
        assert first_client.stun_port == first.port
        assert second_client.stun_port == second.port
        assert first.port != second.port
        first.start("first-password")
        second.start("second-password")

        first_response, first_peer = request_response(first, request)
        second_response, second_peer = request_response(second, request)
        assert first_response == nexxt_lan.stun_success(
            request, first_peer, "first-password"
        )
        assert second_response == nexxt_lan.stun_success(
            request, second_peer, "second-password"
        )
        assert first_response != nexxt_lan.stun_success(
            request, first_peer, "second-password"
        )

        # Releasing one session's endpoint does not affect the other session.
        first.close()
        response, peer = request_response(second, request)
        assert response == nexxt_lan.stun_success(request, peer, "second-password")
    finally:
        first.close()
        second.close()


def test_ephemeral_endpoint_is_advertised_in_its_own_offer(monkeypatch):
    monkeypatch.setattr(
        nexxt_lan, "build_auth_info", lambda *_args, **_kwargs: bytes(104)
    )
    server, session_client = nexxt_lan.open_local_stun_endpoint(CLIENT, port=0)
    try:
        session = nexxt_lan.prepare_session(
            client=session_client, camera=CAMERA, debug=False
        )
        assert session.offer["msg"]["token"] == [
            {"urls": f"stun:127.0.0.1:{server.port}"}
        ]
        server.start(session.ice_password)
    finally:
        server.close()


def test_single_camera_default_keeps_configured_stun_port(monkeypatch):
    created = []

    class FakeStunServer:
        def __init__(self, host, port):
            self.host = host
            self.port = port
            created.append(self)

    monkeypatch.setattr(nexxt_lan, "LocalStunServer", FakeStunServer)
    _server, session_client = nexxt_lan.open_local_stun_endpoint(CLIENT)

    assert created[0].host == "127.0.0.1"
    assert created[0].port == 3478
    assert session_client.stun_port == 3478
