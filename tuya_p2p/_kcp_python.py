from __future__ import annotations

import struct
from dataclasses import dataclass
import operator
from collections.abc import Callable

# Derived from the KCP reference implementation vendored in ``vendor/kcp``.
# Copyright (c) 2017 Lin Wei (skywind3000 at gmail.com).
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from ._kcp_common import (
    IKCP_ASK_SEND,
    IKCP_ASK_TELL,
    IKCP_CMD_ACK,
    IKCP_CMD_PUSH,
    IKCP_CMD_WASK,
    IKCP_CMD_WINS,
    IKCP_DEADLINK,
    IKCP_INTERVAL,
    IKCP_MTU_DEF,
    IKCP_OVERHEAD,
    IKCP_RTO_DEF,
    IKCP_RTO_MAX,
    IKCP_RTO_MIN,
    IKCP_RTO_NDL,
    IKCP_THRESH_INIT,
    IKCP_THRESH_MIN,
    IKCP_WND_RCV,
    IKCP_WND_SND,
    KCPConfig,
    UINT32_MASK,
)


def _u32(v: int) -> int:
    return v & UINT32_MASK


def _itimediff(later: int, earlier: int) -> int:
    v = (later - earlier) & UINT32_MASK
    if v & 0x80000000:
        v -= 0x100000000
    return v


@dataclass(slots=True)
class _Segment:
    conv: int = 0
    cmd: int = 0
    frg: int = 0
    wnd: int = 0
    ts: int = 0
    sn: int = 0
    una: int = 0
    data: bytes = b""
    resendts: int = 0
    rto: int = 0
    fastack: int = 0
    xmit: int = 0

    def encode(self) -> bytes:
        return struct.pack(
            "<IBBHIIII",
            self.conv & UINT32_MASK,
            self.cmd & 0xFF,
            self.frg & 0xFF,
            self.wnd & 0xFFFF,
            self.ts & UINT32_MASK,
            self.sn & UINT32_MASK,
            self.una & UINT32_MASK,
            len(self.data),
        ) + self.data


class PythonKCP:
    """
    Compact pure-Python port of standard KCP semantics.

    The output callback receives one UDP payload at a time. The caller owns
    scheduling and should call update(now_ms).
    """

    def __init__(
        self,
        conv: int,
        output: Callable[[bytes], None],
        config: KCPConfig | None = None,
    ) -> None:
        if not callable(output):
            raise TypeError("output must be callable")

        self.conv = _u32(operator.index(conv))
        self.output = output
        self.config = config or KCPConfig()

        self.mtu = operator.index(self.config.mtu)
        if self.mtu < 50:
            raise ValueError(f"MTU must be at least 50 bytes (got {self.mtu!r})")
        self.mss = self.mtu - IKCP_OVERHEAD

        self.snd_una = 0
        self.snd_nxt = 0
        self.rcv_nxt = 0

        self.ssthresh = IKCP_THRESH_INIT
        self.rx_rttval = 0
        self.rx_srtt = 0
        self.rx_rto = IKCP_RTO_DEF
        self.rx_minrto = IKCP_RTO_MIN

        self.snd_wnd = operator.index(self.config.snd_wnd)
        self.rcv_wnd = operator.index(self.config.rcv_wnd)
        self.rmt_wnd = IKCP_WND_RCV
        self.cwnd = 0
        self.probe = 0

        self.current = 0
        self.interval = max(10, min(5000, operator.index(self.config.interval)))
        self.ts_flush = self.interval
        self.updated = False
        self.ts_probe = 0
        self.probe_wait = 0
        self.dead_link = IKCP_DEADLINK
        self.incr = 0

        self.fastresend = operator.index(self.config.resend)
        self.nocwnd = operator.index(self.config.nc)
        self.nodelay = operator.index(self.config.nodelay)

        self.snd_queue: list[_Segment] = []
        self.rcv_queue: list[_Segment] = []
        self.snd_buf: list[_Segment] = []
        self.rcv_buf: list[_Segment] = []
        self.acklist: list[tuple[int, int]] = []

    def set_nodelay(self, nodelay: int, interval: int, resend: int, nc: int) -> None:
        nodelay = operator.index(nodelay)
        interval = operator.index(interval)
        resend = operator.index(resend)
        nc = operator.index(nc)
        self.nodelay = nodelay
        if nodelay:
            self.rx_minrto = IKCP_RTO_NDL
        else:
            self.rx_minrto = IKCP_RTO_MIN
        if interval >= 0:
            self.interval = max(10, min(5000, interval))
        if resend >= 0:
            self.fastresend = resend
        if nc >= 0:
            self.nocwnd = nc

    def wndsize(self, sndwnd: int, rcvwnd: int) -> None:
        sndwnd = operator.index(sndwnd)
        rcvwnd = operator.index(rcvwnd)
        if sndwnd > 0:
            self.snd_wnd = sndwnd
        if rcvwnd > 0:
            self.rcv_wnd = max(rcvwnd, IKCP_WND_RCV)

    def send(self, data: bytes) -> int:
        payload = bytes(data)
        if not payload:
            return -1
        count = (len(payload) + self.mss - 1) // self.mss
        # The upstream receiver window is also the maximum fragment count.
        if count >= IKCP_WND_RCV:
            return -2
        for i in range(count):
            chunk = payload[i * self.mss : (i + 1) * self.mss]
            self.snd_queue.append(_Segment(frg=count - i - 1, data=chunk))
        return 0

    def recv(self) -> bytes | None:
        if not self.rcv_queue:
            return None

        peeksize = self.peeksize()
        if peeksize < 0:
            return None

        out = bytearray()
        count = 0
        for seg in self.rcv_queue:
            out.extend(seg.data)
            count += 1
            if seg.frg == 0:
                break
        del self.rcv_queue[:count]

        moved = []
        while self.rcv_buf and _itimediff(self.rcv_buf[0].sn, self.rcv_nxt) == 0 and len(self.rcv_queue) < self.rcv_wnd:
            seg = self.rcv_buf.pop(0)
            self.rcv_queue.append(seg)
            self.rcv_nxt = _u32(self.rcv_nxt + 1)
            moved.append(seg)
        return bytes(out)

    def peeksize(self) -> int:
        if not self.rcv_queue:
            return -1
        seg = self.rcv_queue[0]
        if seg.frg == 0:
            return len(seg.data)
        if len(self.rcv_queue) < seg.frg + 1:
            return -1
        total = 0
        for s in self.rcv_queue:
            total += len(s.data)
            if s.frg == 0:
                break
        return total

    def input(self, data: bytes) -> int:
        packet = bytes(data)
        if len(packet) < IKCP_OVERHEAD:
            return -1

        old_una = self.snd_una
        offset = 0
        maxack = 0
        latest_ts = 0
        flag = False

        while len(packet) - offset >= IKCP_OVERHEAD:
            conv, cmd, frg, wnd, ts, sn, una, length = struct.unpack_from("<IBBHIIII", packet, offset)
            offset += IKCP_OVERHEAD
            if conv != self.conv:
                return -1
            if len(packet) - offset < length:
                return -2
            payload = packet[offset:offset + length]
            offset += length

            if cmd not in (IKCP_CMD_PUSH, IKCP_CMD_ACK, IKCP_CMD_WASK, IKCP_CMD_WINS):
                return -3

            self.rmt_wnd = wnd
            self._parse_una(una)
            self._shrink_buf()

            if cmd == IKCP_CMD_ACK:
                if _itimediff(self.current, ts) >= 0:
                    self._update_ack(_itimediff(self.current, ts))
                self._parse_ack(sn)
                self._shrink_buf()
                if not flag:
                    flag = True
                    maxack = sn
                    latest_ts = ts
                elif _itimediff(sn, maxack) > 0:
                    maxack = sn
                    latest_ts = ts

            elif cmd == IKCP_CMD_PUSH:
                if _itimediff(sn, _u32(self.rcv_nxt + self.rcv_wnd)) < 0:
                    self.acklist.append((sn, ts))
                    if _itimediff(sn, self.rcv_nxt) >= 0:
                        self._parse_data(_Segment(
                            conv=conv, cmd=cmd, frg=frg, wnd=wnd, ts=ts,
                            sn=sn, una=una, data=payload
                        ))

            elif cmd == IKCP_CMD_WASK:
                self.probe |= IKCP_ASK_TELL

        if flag:
            self._parse_fastack(maxack, latest_ts)

        if _itimediff(self.snd_una, old_una) > 0:
            if self.cwnd < self.rmt_wnd:
                mss = self.mss
                if self.cwnd < self.ssthresh:
                    self.cwnd += 1
                    self.incr += mss
                else:
                    if self.incr < mss:
                        self.incr = mss
                    self.incr += (mss * mss) // self.incr + (mss // 16)
                    if (self.cwnd + 1) * mss <= self.incr:
                        self.cwnd += 1
                if self.cwnd > self.rmt_wnd:
                    self.cwnd = self.rmt_wnd
                    self.incr = self.rmt_wnd * mss

        return 0

    def update(self, current_ms: int) -> None:
        self.current = _u32(current_ms)
        if not self.updated:
            self.updated = True
            self.ts_flush = self.current

        slap = _itimediff(self.current, self.ts_flush)
        if slap >= 10000 or slap < -10000:
            self.ts_flush = self.current
            slap = 0

        if slap >= 0:
            self.ts_flush = _u32(self.ts_flush + self.interval)
            if _itimediff(self.current, self.ts_flush) >= 0:
                self.ts_flush = _u32(self.current + self.interval)
            self._flush()

    def flush(self) -> None:
        """Immediately emit queued KCP segments using the current timestamp."""
        self._flush()

    def check(self, current_ms: int) -> int:
        current = _u32(current_ms)
        if not self.updated:
            return current

        ts_flush = self.ts_flush
        tm_flush = _itimediff(ts_flush, current)
        if tm_flush >= 10000 or tm_flush < -10000:
            ts_flush = current
        if _itimediff(current, ts_flush) >= 0:
            return current

        tm_packet = 0x7FFFFFFF
        for seg in self.snd_buf:
            diff = _itimediff(seg.resendts, current)
            if diff <= 0:
                return current
            if diff < tm_packet:
                tm_packet = diff

        minimal = min(tm_packet, tm_flush, self.interval)
        return _u32(current + minimal)

    def _wnd_unused(self) -> int:
        if len(self.rcv_queue) < self.rcv_wnd:
            return self.rcv_wnd - len(self.rcv_queue)
        return 0

    def _update_ack(self, rtt: int) -> None:
        if self.rx_srtt == 0:
            self.rx_srtt = rtt
            self.rx_rttval = rtt // 2
        else:
            delta = abs(rtt - self.rx_srtt)
            self.rx_rttval = (3 * self.rx_rttval + delta) // 4
            self.rx_srtt = (7 * self.rx_srtt + rtt) // 8
            if self.rx_srtt < 1:
                self.rx_srtt = 1
        rto = self.rx_srtt + max(self.interval, 4 * self.rx_rttval)
        self.rx_rto = max(self.rx_minrto, min(rto, IKCP_RTO_MAX))

    def _shrink_buf(self) -> None:
        self.snd_una = self.snd_buf[0].sn if self.snd_buf else self.snd_nxt

    def _parse_ack(self, sn: int) -> None:
        if _itimediff(sn, self.snd_una) < 0 or _itimediff(sn, self.snd_nxt) >= 0:
            return
        for i, seg in enumerate(self.snd_buf):
            if sn == seg.sn:
                del self.snd_buf[i]
                break
            if _itimediff(sn, seg.sn) < 0:
                break

    def _parse_una(self, una: int) -> None:
        count = 0
        for seg in self.snd_buf:
            if _itimediff(una, seg.sn) > 0:
                count += 1
            else:
                break
        if count:
            del self.snd_buf[:count]

    def _parse_fastack(self, sn: int, ts: int) -> None:
        if _itimediff(sn, self.snd_una) < 0 or _itimediff(sn, self.snd_nxt) >= 0:
            return
        for seg in self.snd_buf:
            if _itimediff(sn, seg.sn) < 0:
                break
            if sn != seg.sn and _itimediff(ts, seg.ts) >= 0:
                seg.fastack += 1

    def _parse_data(self, newseg: _Segment) -> None:
        sn = newseg.sn
        if _itimediff(sn, _u32(self.rcv_nxt + self.rcv_wnd)) >= 0 or _itimediff(sn, self.rcv_nxt) < 0:
            return

        repeat = False
        insert_idx = len(self.rcv_buf)
        for i in range(len(self.rcv_buf) - 1, -1, -1):
            seg = self.rcv_buf[i]
            if seg.sn == sn:
                repeat = True
                break
            if _itimediff(sn, seg.sn) > 0:
                insert_idx = i + 1
                break
            insert_idx = i

        if not repeat:
            self.rcv_buf.insert(insert_idx, newseg)

        while self.rcv_buf and _itimediff(self.rcv_buf[0].sn, self.rcv_nxt) == 0 and len(self.rcv_queue) < self.rcv_wnd:
            seg = self.rcv_buf.pop(0)
            self.rcv_queue.append(seg)
            self.rcv_nxt = _u32(self.rcv_nxt + 1)

    def _flush(self) -> None:
        wnd = self._wnd_unused()
        packets: list[bytes] = []
        buf = bytearray()

        def emit(seg: _Segment) -> None:
            nonlocal buf
            encoded = seg.encode()
            if len(buf) + len(encoded) > self.mtu:
                if buf:
                    packets.append(bytes(buf))
                buf = bytearray()
            buf.extend(encoded)

        for sn, ts in self.acklist:
            emit(_Segment(
                conv=self.conv, cmd=IKCP_CMD_ACK, wnd=wnd,
                ts=ts, sn=sn, una=self.rcv_nxt
            ))
        self.acklist.clear()

        if self.rmt_wnd == 0:
            if self.probe_wait == 0:
                self.probe_wait = 7000
                self.ts_probe = _u32(self.current + self.probe_wait)
            elif _itimediff(self.current, self.ts_probe) >= 0:
                self.probe_wait += self.probe_wait // 2
                if self.probe_wait > 120000:
                    self.probe_wait = 120000
                self.ts_probe = _u32(self.current + self.probe_wait)
                self.probe |= IKCP_ASK_SEND
        else:
            self.ts_probe = 0
            self.probe_wait = 0

        if self.probe & IKCP_ASK_SEND:
            emit(_Segment(conv=self.conv, cmd=IKCP_CMD_WASK, wnd=wnd, una=self.rcv_nxt))
        if self.probe & IKCP_ASK_TELL:
            emit(_Segment(conv=self.conv, cmd=IKCP_CMD_WINS, wnd=wnd, una=self.rcv_nxt))
        self.probe = 0

        cwnd = min(self.snd_wnd, self.rmt_wnd)
        if not self.nocwnd:
            cwnd = min(self.cwnd, cwnd)

        while _itimediff(self.snd_nxt, _u32(self.snd_una + cwnd)) < 0 and self.snd_queue:
            newseg = self.snd_queue.pop(0)
            newseg.conv = self.conv
            newseg.cmd = IKCP_CMD_PUSH
            newseg.wnd = wnd
            newseg.ts = self.current
            newseg.sn = self.snd_nxt
            self.snd_nxt = _u32(self.snd_nxt + 1)
            newseg.una = self.rcv_nxt
            newseg.resendts = self.current
            newseg.rto = self.rx_rto
            newseg.fastack = 0
            newseg.xmit = 0
            self.snd_buf.append(newseg)

        resent = self.fastresend if self.fastresend > 0 else 0x7FFFFFFF
        rtomin = self.rx_rto // 8 if not self.nodelay else 0
        lost = False
        change = 0

        for seg in self.snd_buf:
            needsend = False
            if seg.xmit == 0:
                needsend = True
                seg.xmit += 1
                seg.rto = self.rx_rto
                seg.resendts = _u32(self.current + seg.rto + rtomin)
            elif _itimediff(self.current, seg.resendts) >= 0:
                needsend = True
                seg.xmit += 1
                if not self.nodelay:
                    seg.rto += max(seg.rto, self.rx_rto)
                else:
                    seg.rto += self.rx_rto // 2
                seg.resendts = _u32(self.current + seg.rto)
                lost = True
            elif seg.fastack >= resent:
                needsend = True
                seg.xmit += 1
                seg.fastack = 0
                seg.resendts = _u32(self.current + seg.rto)
                change += 1

            if needsend:
                seg.ts = self.current
                seg.wnd = wnd
                seg.una = self.rcv_nxt
                emit(seg)
                if seg.xmit >= self.dead_link:
                    pass

        if buf:
            packets.append(bytes(buf))

        for packet in packets:
            self.output(packet)

        if change:
            inflight = _u32(self.snd_nxt - self.snd_una)
            self.ssthresh = max(inflight // 2, IKCP_THRESH_MIN)
            self.cwnd = self.ssthresh + resent
            self.incr = self.cwnd * self.mss

        if lost:
            self.ssthresh = max(cwnd // 2, IKCP_THRESH_MIN)
            self.cwnd = 1
            self.incr = self.mss

        if self.cwnd < 1:
            self.cwnd = 1
            self.incr = self.mss
