"""Build definition for the vendored upstream KCP C implementation."""

from cffi import FFI

ffibuilder = FFI()
ffibuilder.cdef("""
    typedef unsigned int IUINT32;
    typedef signed int IINT32;

    typedef struct IKCPCB {
        IUINT32 conv, mtu, mss, state;
        IUINT32 snd_una, snd_nxt, rcv_nxt;
        IUINT32 ts_recent, ts_lastack, ssthresh;
        IINT32 rx_rttval, rx_srtt, rx_rto, rx_minrto;
        IUINT32 snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe;
        IUINT32 current, interval, ts_flush, xmit;
        IUINT32 nrcv_buf, nsnd_buf;
        IUINT32 nrcv_que, nsnd_que;
        IUINT32 nodelay, updated;
        IUINT32 ts_probe, probe_wait;
        IUINT32 dead_link, incr;
        ...;
    } ikcpcb;

    typedef int (*ikcp_output_callback)(const char *, int, ikcpcb *, void *);

    ikcpcb *ikcp_create(IUINT32 conv, void *user);
    void ikcp_release(ikcpcb *kcp);
    void ikcp_setoutput(ikcpcb *kcp, ikcp_output_callback output);
    int ikcp_recv(ikcpcb *kcp, char *buffer, int len);
    int ikcp_send(ikcpcb *kcp, const char *buffer, int len);
    void ikcp_update(ikcpcb *kcp, IUINT32 current);
    IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current);
    int ikcp_input(ikcpcb *kcp, const char *data, long size);
    void ikcp_flush(ikcpcb *kcp);
    int ikcp_peeksize(const ikcpcb *kcp);
    int ikcp_setmtu(ikcpcb *kcp, int mtu);
    int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd);
    int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc);
    """)
ffibuilder.set_source(
    "tuya_p2p._kcp_native",
    '#include "ikcp.h"',
    include_dirs=["tuya_p2p/vendor/kcp"],
    sources=["tuya_p2p/vendor/kcp/ikcp.c"],
)


if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
