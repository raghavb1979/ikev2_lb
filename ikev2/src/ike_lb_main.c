#include "ike_lb.h"
#include "ike_lb_pcap.h"
#include "ike_msg.h"
#include "ikev2_common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#define RECV_BUF IKE_MAX_PACKET
#define MAX_POLL_FDS (2 + IKE_LB_MAX_BACKENDS)

static struct ike_lb_session g_sessions[IKE_LB_MAX_SESSIONS];
static int g_backend_fds[IKE_LB_MAX_BACKENDS];
static int g_listen_fd500 = -1;
static int g_listen_fd4500 = -1;

static int spi_is_zero(const ike_spi_t spi)
{
    for (int i = 0; i < IKE_SPI_LEN; i++)
        if (spi[i])
            return 0;
    return 1;
}

static int buffer_contains_spi(const uint8_t *buf, size_t len, const ike_spi_t spi)
{
    if (len < IKE_SPI_LEN)
        return 0;
    for (size_t i = 0; i + IKE_SPI_LEN <= len; i++) {
        if (memcmp(buf + i, spi, IKE_SPI_LEN) == 0)
            return 1;
    }
    return 0;
}

#define IKE_LB_MAX_UDP IKE_MAX_PACKET
/* Reject backend garbage; legitimate IKEv2 fits well under 8 KiB in this interop. */
#define IKE_LB_SANE_IKE 8192

static int ike_header_plausible(const uint8_t *ike, size_t ike_len)
{
    struct ike_header hdr;

    if (ike_len < IKE_HEADER_LEN || ike_header_decode(ike, ike_len, &hdr) != 0)
        return 0;
    if (hdr.version != IKE_VERSION_BYTE)
        return 0;
    if (hdr.length < IKE_HEADER_LEN || hdr.length > ike_len || hdr.length > IKE_LB_SANE_IKE)
        return 0;
    if (hdr.exchange_type != IKE_EXCHANGE_IKE_SA_INIT &&
        hdr.exchange_type != IKE_EXCHANGE_IKE_AUTH)
        return 0;
    return 1;
}

static size_t find_ike_offset(const uint8_t *buf, size_t len)
{
    /* Plain IKEv2 or 4-byte NAT-T non-ESP marker before header. */
    if (len >= IKE_HEADER_LEN && ike_header_plausible(buf, len))
        return 0;
    if (len >= IKE_HEADER_LEN + 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0 &&
        ike_header_plausible(buf + 4, len - 4))
        return 4;
    /* Scan small prefix (some stacks add extra padding before IKE). */
    for (size_t off = 0; off + IKE_HEADER_LEN <= len && off <= 32; off++) {
        if (ike_header_plausible(buf + off, len - off))
            return off;
    }
    return len;
}

static size_t strip_natt_marker(const uint8_t *buf, size_t len)
{
    size_t off = find_ike_offset(buf, len);
    return (off < len) ? off : 0;
}

static int parse_ike_frame(const uint8_t *buf, size_t len, size_t *offset_out,
                           struct ike_header *hdr_out, size_t *frame_len_out)
{
    size_t offset;
    const uint8_t *ike;
    size_t ike_len;
    struct ike_header hdr;

    if (!offset_out || !hdr_out || !frame_len_out)
        return -1;

    offset = strip_natt_marker(buf, len);
    ike = buf + offset;
    ike_len = len - offset;
    if (ike_len < IKE_HEADER_LEN || ike_header_decode(ike, ike_len, &hdr) != 0)
        return -1;
    if (hdr.version != IKE_VERSION_BYTE) {
        if (getenv("IKE_LB_DEBUG")) {
            fprintf(stderr, "ike frame: bad version %02x at off %zu (b17=%02x b21=%02x) hex:",
                    hdr.version, offset, len > 17 ? buf[17] : 0, len > 21 ? buf[21] : 0);
            for (size_t i = 0; i < 32 && i < len; i++)
                fprintf(stderr, " %02x", buf[i]);
            fputc('\n', stderr);
        }
        return -1;
    }
    if (hdr.length < IKE_HEADER_LEN || hdr.length > ike_len || hdr.length > IKE_LB_SANE_IKE) {
        if (getenv("IKE_LB_DEBUG"))
            fprintf(stderr, "ike frame: bad length %u (udp %zu, ike %zu, off %zu)\n",
                    hdr.length, len, ike_len, offset);
        return -1;
    }

    *offset_out = offset;
    *hdr_out = hdr;
    *frame_len_out = offset + hdr.length;
    return 0;
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int open_udp_listener(const char *host, uint16_t port)
{
    struct sockaddr_in addr;
    int fd, on = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int init_backend_sockets(struct ike_lb_config *cfg)
{
    for (int i = 0; i < cfg->num_backends; i++) {
        struct sockaddr_in bind_addr;
        int on = 1;
        uint16_t relay_port = (uint16_t)(6200 + i);

        g_backend_fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_backend_fds[i] < 0)
            return -1;
        setsockopt(g_backend_fds[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(relay_port);
        if (inet_pton(AF_INET, cfg->backends[i].host, &bind_addr.sin_addr) != 1 ||
            bind(g_backend_fds[i], (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            close(g_backend_fds[i]);
            g_backend_fds[i] = -1;
            return -1;
        }
        if (set_nonblock(g_backend_fds[i]) < 0) {
            close(g_backend_fds[i]);
            g_backend_fds[i] = -1;
            return -1;
        }
    }
    return 0;
}

static int lookup_backend_session(int backend_idx, const ike_spi_t init_spi,
                                  const ike_spi_t resp_spi)
{
    int sess_idx;

    sess_idx = ike_lb_session_lookup_spi(g_sessions, IKE_LB_MAX_SESSIONS, backend_idx,
                                         init_spi, resp_spi);
    if (sess_idx >= 0)
        return sess_idx;

    for (size_t i = 0; i < IKE_LB_MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use || g_sessions[i].backend_index != backend_idx)
            continue;
        if (memcmp(g_sessions[i].initiator_spi, init_spi, IKE_SPI_LEN) != 0)
            continue;
        if (!spi_is_zero(resp_spi))
            ike_lb_session_set_responder_spi(g_sessions, IKE_LB_MAX_SESSIONS, (int)i,
                                             resp_spi);
        return (int)i;
    }

    return ike_lb_session_lookup_single_backend(g_sessions, IKE_LB_MAX_SESSIONS, backend_idx);
}

static void sockaddr_v4(const struct sockaddr_storage *ss, socklen_t len,
                        char *ip, size_t ipcap, uint16_t *port)
{
    const struct sockaddr_in *sin;

    if (len < sizeof(struct sockaddr_in) || ss->ss_family != AF_INET) {
        strncpy(ip, "0.0.0.0", ipcap);
        *port = 0;
        return;
    }
    sin = (const struct sockaddr_in *)ss;
    inet_ntop(AF_INET, &sin->sin_addr, ip, (socklen_t)ipcap);
    *port = ntohs(sin->sin_port);
}

static int is_natt_keepalive(const uint8_t *buf, size_t len)
{
    return len == 1 && buf[0] == 0xff;
}

static int forward_to_backend(struct ike_lb_config *cfg, int idx, const uint8_t *pkt,
                              size_t len, const char *src_ip, uint16_t src_port,
                              int use_natt)
{
    ssize_t n;
    const struct sockaddr_storage *dst;
    uint16_t dst_port;

    if (idx < 0 || idx >= cfg->num_backends)
        return -1;
    dst = use_natt ? &cfg->backends[idx].natt_addr : &cfg->backends[idx].addr;
    dst_port = use_natt ? cfg->backends[idx].natt_port : cfg->backends[idx].port;
    if (ike_lb_pcap_is_open())
        ike_lb_pcap_write(pkt, len, src_ip, src_port, cfg->backends[idx].host, dst_port);
    n = sendto(g_backend_fds[idx], pkt, len, 0, (struct sockaddr *)dst, cfg->backends[idx].addr_len);
    return (n == (ssize_t)len) ? 0 : -1;
}

static int relay_to_client(struct ike_lb_config *cfg, int sess_idx,
                           const uint8_t *pkt, size_t len, size_t send_len,
                           const char *src_ip, uint16_t src_port)
{
    ssize_t n;
    int fd;
    char dst_ip[64];
    uint16_t dst_port;
    struct sockaddr_storage *caddr = &g_sessions[sess_idx].client_addr;
    struct sockaddr_in *csin;

    if (sess_idx < 0 || !g_sessions[sess_idx].in_use)
        return -1;
    if (send_len == 0 || send_len > len)
        send_len = len;

    sockaddr_v4(&g_sessions[sess_idx].client_addr, g_sessions[sess_idx].client_len,
                dst_ip, sizeof(dst_ip), &dst_port);

    {
        fd = g_sessions[sess_idx].client_listen_fd;
        if (fd < 0)
            fd = g_listen_fd500;
        /* After IKE_SA_INIT the spoke moves to NAT-T :4500; session may still record :500. */
        if (!spi_is_zero(g_sessions[sess_idx].responder_spi) &&
            dst_port != cfg->listen_natt_port && caddr->ss_family == AF_INET) {
            csin = (struct sockaddr_in *)caddr;
            csin->sin_port = htons(cfg->listen_natt_port);
            dst_port = cfg->listen_natt_port;
        }
        if (dst_port == cfg->listen_natt_port && g_listen_fd4500 >= 0)
            fd = g_listen_fd4500;
    }

    (void)src_ip;
    (void)src_port;
    if (ike_lb_pcap_is_open())
        ike_lb_pcap_write(pkt, send_len, src_ip, src_port, dst_ip, dst_port);

    n = sendto(fd, pkt, send_len, 0,
               (struct sockaddr *)&g_sessions[sess_idx].client_addr,
               g_sessions[sess_idx].client_len);
    if (n != (ssize_t)send_len && getenv("IKE_LB_DEBUG"))
        fprintf(stderr, "relay sendto %s:%u failed: %s\n", dst_ip, dst_port, strerror(errno));
    return (n == (ssize_t)send_len) ? 0 : -1;
}

static int handle_client_keepalive(struct ike_lb_config *cfg, int listen_fd,
                                   const uint8_t *buf, size_t len,
                                   const struct sockaddr_storage *client,
                                   socklen_t client_len)
{
    int sess_idx;
    int use_natt = (listen_fd == g_listen_fd4500 && g_listen_fd4500 >= 0);

    (void)len;
    sess_idx = ike_lb_session_lookup_client(g_sessions, IKE_LB_MAX_SESSIONS, client, client_len);
    if (sess_idx < 0)
        return 0;
    ike_lb_session_touch(g_sessions, IKE_LB_MAX_SESSIONS, sess_idx);
  return forward_to_backend(cfg, g_sessions[sess_idx].backend_index, buf, 1,
                              cfg->listen_host, use_natt ? cfg->listen_natt_port : cfg->listen_port,
                              use_natt);
}

static int handle_client_packet(struct ike_lb_config *cfg, int listen_fd,
                                uint16_t listen_port,
                                const uint8_t *buf, size_t len,
                                const struct sockaddr_storage *client,
                                socklen_t client_len)
{
    char client_ip[64];
    uint16_t client_port;
    struct ike_header hdr;
    size_t offset;
    int backend_idx, sess_idx;
    int use_natt = (listen_fd == g_listen_fd4500 && g_listen_fd4500 >= 0);
    const uint8_t *ike_pkt = buf;
    size_t ike_len = len;

    if (is_natt_keepalive(buf, len))
        return handle_client_keepalive(cfg, listen_fd, buf, len, client, client_len);

    offset = strip_natt_marker(buf, len);
    ike_pkt = buf + offset;
    ike_len = len - offset;

    if (ike_len < IKE_HEADER_LEN)
        return -1;
    if (ike_header_decode(ike_pkt, ike_len, &hdr) != 0)
        return -1;

    sockaddr_v4(client, client_len, client_ip, sizeof(client_ip), &client_port);
    if (ike_lb_pcap_is_open())
        ike_lb_pcap_write(buf, len, client_ip, client_port, cfg->listen_host, listen_port);

    sess_idx = ike_lb_session_lookup(g_sessions, IKE_LB_MAX_SESSIONS, client,
                                     client_len, hdr.initiator_spi,
                                     hdr.responder_spi);
    if (sess_idx < 0) {
        sess_idx = ike_lb_session_lookup_natt(g_sessions, IKE_LB_MAX_SESSIONS, client,
                                              client_len, hdr.initiator_spi,
                                              hdr.responder_spi);
        if (sess_idx >= 0)
            ike_lb_session_update_client(g_sessions, IKE_LB_MAX_SESSIONS, sess_idx,
                                         client, client_len, listen_fd);
    }
    if (sess_idx >= 0) {
        backend_idx = g_sessions[sess_idx].backend_index;
        ike_lb_session_touch(g_sessions, IKE_LB_MAX_SESSIONS, sess_idx);
        if (!spi_is_zero(hdr.responder_spi))
            ike_lb_session_set_responder_spi(g_sessions, IKE_LB_MAX_SESSIONS,
                                             sess_idx, hdr.responder_spi);
    } else {
        backend_idx = ike_lb_pick_backend(cfg, hdr.initiator_spi);
        if (backend_idx < 0)
            return -1;
        sess_idx = ike_lb_session_bind(g_sessions, IKE_LB_MAX_SESSIONS, client,
                                       client_len, hdr.initiator_spi, backend_idx,
                                       listen_fd);
        if (sess_idx < 0)
            return -1;
        fprintf(stderr, "new IKE session -> backend %d (%s:%u)\n", backend_idx,
                cfg->backends[backend_idx].host, cfg->backends[backend_idx].port);
    }

    (void)listen_fd;
    return forward_to_backend(cfg, backend_idx, buf, len, cfg->listen_host, listen_port, use_natt);
}

static int handle_backend_packet(struct ike_lb_config *cfg, int backend_idx,
                                 const uint8_t *buf, size_t len)
{
    struct ike_header hdr;
    size_t offset;
    size_t frame_len;
    int sess_idx;
    const char *why = NULL;

    if (is_natt_keepalive(buf, len)) {
        for (size_t i = 0; i < IKE_LB_MAX_SESSIONS; i++) {
            if (!g_sessions[i].in_use || g_sessions[i].backend_index != backend_idx)
                continue;
            relay_to_client(cfg, (int)i, buf, len, len, cfg->backends[backend_idx].host,
                            cfg->backends[backend_idx].natt_port);
        }
        return 0;
    }

    if (len > IKE_LB_SANE_IKE) {
        if (getenv("IKE_LB_DEBUG"))
            fprintf(stderr, "ignore %zd byte backend UDP (oversized)\n", len);
        return 0;
    }

    if (parse_ike_frame(buf, len, &offset, &hdr, &frame_len) != 0) {
        sess_idx = ike_lb_session_lookup_single_backend(g_sessions, IKE_LB_MAX_SESSIONS,
                                                        backend_idx);
        if (sess_idx >= 0 && len <= IKE_LB_SANE_IKE && !is_natt_keepalive(buf, len) &&
            buffer_contains_spi(buf, len, g_sessions[sess_idx].initiator_spi))
            return relay_to_client(cfg, sess_idx, buf, len, len, cfg->listen_host,
                                   cfg->listen_port);
        why = "invalid IKE frame";
        goto drop;
    }

    sess_idx = lookup_backend_session(backend_idx, hdr.initiator_spi, hdr.responder_spi);
    if (sess_idx < 0) {
        why = "no session for SPI";
        goto drop;
    }

    if (ike_lb_pcap_is_open())
        ike_lb_pcap_write(buf, len, cfg->backends[backend_idx].host,
                          cfg->backends[backend_idx].port, cfg->listen_host,
                          cfg->listen_port);

    ike_lb_session_touch(g_sessions, IKE_LB_MAX_SESSIONS, sess_idx);
    if (relay_to_client(cfg, sess_idx, buf, len, len, cfg->listen_host, cfg->listen_port) != 0) {
        why = "relay sendto";
        goto drop;
    }
    if (getenv("IKE_LB_DEBUG")) {
        char ip[64];
        uint16_t port;
        sockaddr_v4(&g_sessions[sess_idx].client_addr, g_sessions[sess_idx].client_len,
                    ip, sizeof(ip), &port);
        fprintf(stderr, "relayed %zu bytes to %s:%u\n", len, ip, port);
    }
    return 0;

drop:
    if (getenv("IKE_LB_DEBUG") && why)
        fprintf(stderr, "drop %zd byte backend IKE (%s)\n", len, why);
    return -1;
}

static void poll_loop(struct ike_lb_config *cfg, int fd500, int fd4500)
{
    struct pollfd pf[MAX_POLL_FDS];
    int nfds = 0;
    uint8_t buf[RECV_BUF];
    int i;

    g_listen_fd500 = fd500;
    g_listen_fd4500 = fd4500;

    pf[nfds].fd = fd500;
    pf[nfds].events = POLLIN;
    nfds++;

    if (fd4500 >= 0 && fd4500 != fd500) {
        pf[nfds].fd = fd4500;
        pf[nfds].events = POLLIN;
        nfds++;
    }

    for (i = 0; i < cfg->num_backends; i++) {
        pf[nfds].fd = g_backend_fds[i];
        pf[nfds].events = POLLIN;
        nfds++;
    }

    for (;;) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n;

        if (poll(pf, (nfds_t)nfds, -1) < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }

        for (i = 0; i < nfds; i++) {
            if (!(pf[i].revents & POLLIN))
                continue;

            for (;;) {
                peer_len = sizeof(peer);
                n = recvfrom(pf[i].fd, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&peer, &peer_len);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    perror("recvfrom");
                    break;
                }
                if (n == 0)
                    break;
                if ((size_t)n > IKE_LB_MAX_UDP) {
                    if (getenv("IKE_LB_DEBUG"))
                        fprintf(stderr, "ignore %zd byte UDP (max %d)\n", n, IKE_LB_MAX_UDP);
                    continue;
                }

                if (pf[i].fd == fd500 || pf[i].fd == fd4500) {
                    uint16_t lp = (pf[i].fd == fd4500 && fd4500 >= 0) ? cfg->listen_natt_port
                                                                      : cfg->listen_port;
                    if (handle_client_packet(cfg, pf[i].fd, lp, buf, (size_t)n, &peer,
                                             peer_len) != 0)
                        fprintf(stderr, "drop %zd byte client IKE packet\n", n);
                } else {
                    int b;
                    for (b = 0; b < cfg->num_backends; b++) {
                        if (pf[i].fd == g_backend_fds[b]) {
                            if (getenv("IKE_LB_DEBUG"))
                                fprintf(stderr, "backend %d recv %zd bytes\n", b, n);
                            if (handle_backend_packet(cfg, b, buf, (size_t)n) != 0) {
                                if (!getenv("IKE_LB_DEBUG"))
                                    fprintf(stderr, "drop %zd byte backend IKE packet\n", n);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    struct ike_lb_config cfg;
    const char *config_path = "config/ike-lb.conf";
    const char *pcap_path = NULL;
    int fd500, fd4500 = -1;
    int ai;

    for (ai = 1; ai < argc; ai++) {
        if (strcmp(argv[ai], "--pcap") == 0 && ai + 1 < argc) {
            pcap_path = argv[++ai];
        } else if (argv[ai][0] != '-') {
            config_path = argv[ai];
        }
    }

    ike_lb_session_init(g_sessions, IKE_LB_MAX_SESSIONS);
    memset(g_backend_fds, -1, sizeof(g_backend_fds));

    if (ike_lb_config_load(&cfg, config_path) != 0) {
        fprintf(stderr, "config load failed (%s); using 127.0.0.1:5001,5002\n",
                config_path);
        ike_lb_config_set_defaults(&cfg);
        strcpy(cfg.backends[0].host, "127.0.0.1");
        cfg.backends[0].port = 5001;
        cfg.backends[0].addr_len = sizeof(cfg.backends[0].addr);
        inet_pton(AF_INET, "127.0.0.1",
                  &((struct sockaddr_in *)&cfg.backends[0].addr)->sin_addr);
        ((struct sockaddr_in *)&cfg.backends[0].addr)->sin_family = AF_INET;
        ((struct sockaddr_in *)&cfg.backends[0].addr)->sin_port = htons(5001);
        cfg.backends[0].natt_port = 4500;
        memcpy(&cfg.backends[0].natt_addr, &cfg.backends[0].addr, sizeof(cfg.backends[0].addr));
        ((struct sockaddr_in *)&cfg.backends[0].natt_addr)->sin_port = htons(4500);
        cfg.backends[0].enabled = 1;
        strcpy(cfg.backends[1].host, "127.0.0.1");
        cfg.backends[1].port = 5002;
        cfg.backends[1].addr_len = sizeof(cfg.backends[1].addr);
        inet_pton(AF_INET, "127.0.0.1",
                  &((struct sockaddr_in *)&cfg.backends[1].addr)->sin_addr);
        ((struct sockaddr_in *)&cfg.backends[1].addr)->sin_family = AF_INET;
        ((struct sockaddr_in *)&cfg.backends[1].addr)->sin_port = htons(5002);
        cfg.backends[1].natt_port = 4500;
        memcpy(&cfg.backends[1].natt_addr, &cfg.backends[1].addr, sizeof(cfg.backends[1].addr));
        ((struct sockaddr_in *)&cfg.backends[1].natt_addr)->sin_port = htons(4500);
        cfg.backends[1].enabled = 1;
        cfg.num_backends = 2;
        cfg.listen_port = 5000;
        strncpy(cfg.listen_host, "127.0.0.1", sizeof(cfg.listen_host) - 1);
    }

    if (init_backend_sockets(&cfg) != 0) {
        perror("backend sockets");
        return 1;
    }

    if (pcap_path && ike_lb_pcap_open(pcap_path) != 0) {
        fprintf(stderr, "failed to open pcap: %s\n", pcap_path);
        return 1;
    }

    fd500 = open_udp_listener(cfg.listen_host, cfg.listen_port);
    if (fd500 < 0) {
        perror("bind ike");
        return 1;
    }
    if (cfg.listen_natt_port != cfg.listen_port) {
        fd4500 = open_udp_listener(cfg.listen_host, cfg.listen_natt_port);
        if (fd4500 < 0)
            fprintf(stderr, "warning: NAT-T port %u not bound\n", cfg.listen_natt_port);
    }

    printf("ike-lb limits: max_sessions=%d max_backends=%d session_timeout=%ds\n",
           IKE_LB_MAX_SESSIONS, IKE_LB_MAX_BACKENDS, IKE_LB_SESSION_TIMEOUT);
    printf("ike-lb listening %s:%u (NAT-T %u), %d backends\n", cfg.listen_host,
           cfg.listen_port, cfg.listen_natt_port, cfg.num_backends);
    for (int i = 0; i < cfg.num_backends; i++)
        printf("  [%d] %s:%u\n", i, cfg.backends[i].host, cfg.backends[i].port);
    if (pcap_path)
        printf("ike-lb pcap recording: %s\n", pcap_path);

    poll_loop(&cfg, fd500, fd4500);
    ike_lb_pcap_close();
    close(fd500);
    if (fd4500 >= 0)
        close(fd4500);
    return 0;
}
