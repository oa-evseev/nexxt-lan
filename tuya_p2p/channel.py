from __future__ import annotations

from collections.abc import Callable

from .kcp import KCP, KCPConfig
from .mode3 import Mode3Codec


class Mode3Channel:
    """
    Complete mode-3 framing around a KCP instance.

    Outbound:
        plaintext
          -> PKCS#7
          -> AES-128-CBC
          -> IV || ciphertext
          -> KCP
          -> HMAC-SHA1(KCP datagram)

    Inbound performs the exact reverse order.
    """

    def __init__(
        self,
        *,
        key: bytes,
        conv: int,
        output: Callable[[bytes], None],
        kcp_config: KCPConfig | None = None,
    ) -> None:
        self.codec = Mode3Codec(key)
        self._wire_output = output
        self.kcp = KCP(conv, self._kcp_output, config=kcp_config)

    def _kcp_output(self, datagram: bytes) -> None:
        self._wire_output(self.codec.sign(datagram))

    def send(self, plaintext: bytes, *, iv: bytes | None = None) -> int:
        application_payload = self.codec.encrypt(plaintext, iv=iv)
        return self.kcp.send(application_payload)

    def input(self, wire_datagram: bytes) -> int:
        kcp_datagram = self.codec.verify(wire_datagram)
        return self.kcp.input(kcp_datagram)

    def recv(self) -> bytes | None:
        application_payload = self.kcp.recv()
        if application_payload is None:
            return None
        return self.codec.decrypt(application_payload)

    def update(self, now_ms: int) -> None:
        self.kcp.update(now_ms)

    def flush(self) -> None:
        """Immediately flush queued KCP segments without changing KCP time."""
        self.kcp.flush()

    def check(self, now_ms: int) -> int:
        return self.kcp.check(now_ms)
