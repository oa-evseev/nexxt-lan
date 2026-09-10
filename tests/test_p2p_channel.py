import pytest

from tuya_p2p.channel import Mode3Channel
from tuya_p2p.kcp import KCPConfig, native_available, using_backend

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
IV = bytes.fromhex("ffeeddccbbaa99887766554433221100")


def test_two_channels_roundtrip():
    a_out = []
    b_out = []

    cfg = KCPConfig(nodelay=1, interval=20, resend=2, nc=1)

    a = Mode3Channel(key=KEY, conv=0x11223344, output=a_out.append, kcp_config=cfg)
    b = Mode3Channel(key=KEY, conv=0x11223344, output=b_out.append, kcp_config=cfg)

    message = b"hello mode3"
    assert a.send(message, iv=IV) == 0

    a.update(0)
    assert a_out

    for packet in a_out:
        assert b.input(packet) == 0

    b.update(0)
    assert b.recv() == message


@pytest.mark.skipif(not native_available(), reason="native KCP extension is not built")
def test_global_python_backend_override_reaches_mode3_channel():
    """A normal upper-level construction must not select native under override."""
    with using_backend("python"):
        channel = Mode3Channel(key=KEY, conv=1, output=lambda _: None)

    assert type(channel.kcp).__name__ == "PythonKCP"


def test_channel_fragments_and_reassembles_out_of_order_datagrams():
    outbound = []
    config = KCPConfig(mtu=64, nodelay=1, interval=20, resend=2, nc=1)
    sender = Mode3Channel(key=KEY, conv=7, output=outbound.append, kcp_config=config)
    receiver = Mode3Channel(key=KEY, conv=7, output=lambda _: None, kcp_config=config)
    message = bytes(range(160))

    assert sender.send(message, iv=IV) == 0
    sender.update(100)
    assert len(outbound) > 1

    for datagram in reversed(outbound):
        assert receiver.input(datagram) == 0

    assert receiver.recv() == message
    assert receiver.recv() is None


def test_channel_retransmits_a_lost_datagram_without_duplicate_delivery():
    outbound = []
    config = KCPConfig(nodelay=1, interval=20, resend=2, nc=1)
    sender = Mode3Channel(key=KEY, conv=9, output=outbound.append, kcp_config=config)
    receiver = Mode3Channel(key=KEY, conv=9, output=lambda _: None, kcp_config=config)

    sender.send(b"survives packet loss", iv=IV)
    sender.update(0)
    first_attempt = outbound.pop()

    sender.update(200)
    assert outbound
    retransmission = outbound.pop()
    assert (
        retransmission != first_attempt
    )  # KCP timestamp changed; payload remains valid.

    assert receiver.input(retransmission) == 0
    assert receiver.input(retransmission) == 0
    assert receiver.recv() == b"survives packet loss"
    assert receiver.recv() is None


def test_channel_rejects_wrong_key_and_conversation_id():
    outbound = []
    config = KCPConfig(nc=1)
    sender = Mode3Channel(key=KEY, conv=1, output=outbound.append, kcp_config=config)
    sender.send(b"secret", iv=IV)
    sender.update(0)

    wrong_key = Mode3Channel(key=b"z" * 16, conv=1, output=lambda _: None)
    with pytest.raises(ValueError, match="HMAC"):
        wrong_key.input(outbound[0])

    wrong_conv = Mode3Channel(key=KEY, conv=2, output=lambda _: None)
    assert wrong_conv.input(outbound[0]) == -1
