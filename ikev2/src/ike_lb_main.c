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

static size_t strip_natt_marker(uint8_t *buf, size_t len)
{
    if (len >= 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0)
        return 4;
    return 0;
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
    return fd;
}

static int init_backend_sockets(struct ike_lb_config *cfg)
{
    for (int i = 0; i < cfg->num_backends; i++) {
        g_backend_fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_backend_fds[i] < 0)
            return -1;
    }
    return 0;
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

static int forward_to_backend(struct ike_lb_config *cfg, int idx, const uint8_t *pkt,
                              size_t len, const char *src_ip, uint16_t src_port)
{
    ssize_t n;
    if (idx < 0 || idx >= cfg->num_backends)
        return -1;
    if (ike_lb_pcap_is_open())
        ike_lb_pcap_write(pkt, len, src_ip, src_port, cfg->backends[idx].host,
                          cfg->backends[idx].port);
    n = sendto(g_backend_fds[idx], pkt, len, 0,
               (struct sockaddr *)&cfg->backends[idx].addr,
               cfg->backends[idx].addr_len);
    return (n == (ssize_t)len) ? 0 : -1;
}

static int relay_to_client(struct ike_lb_config *cfg, int sess_idx,
                           const uint8_t *pkt, size_t len,
                           const char *src_ip, uint16_t src_port)
{
    ssize_t n;
    int fd;
    char dst_ip[64];
    uint16_t dst_port;

    (void)cfg;
    if (sess_idx < 0 || !g_sessions[sess_idx].in_use)
        return -1;

    fd = g_sessions[sess_idx].client_listen_fd;
    if (fd < 0)
        fd = g_listen_fd500;

    sockaddr_v4(&g_sessions[sess_idx].client_addr, g_sessions[sess_idx].client_len,
                dst_ip, sizeof(dst_ip), &dst_port);
    if (ike_lb_pcap_is_open())
        ike_lb_pcap_write(pkt, len, src_ip, src_port, dst_ip, dst_port);

    n = sendto(fd, pkt, len, 0,
               (struct sockaddr *)&g_sessions[sess_idx].client_addr,
               g_sessions[sess_idx].client_len);
    return (n == (ssize_t)len) ? 0 : -1;
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
    const uint8_t *ike_pkt = buf;
    size_t ike_len = len;

    offset = strip_natt_marker((uint8_t *)buf, len);
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
    return forward_to_backend(cfg, backend_idx, buf, len, cfg->listen_host, listen_port);
}

static int handle_backend_packet(struct ike_lb_config *cfg, int backend_idx,
                                 const uint8_t *buf, size_t len)
{
    struct ike_header hdr;
    size_t offset;
    int sess_idx;
    const uint8_t *ike_pkt = buf;
    size_t ike_len = len;

    (void)cfg;
    offset = strip_natt_marker((uint8_t *)buf, len);
    ike_pkt = buf + offset;
    ike_len = len - offset;

    if (ike_len < IKE_HEADER_LEN)
        return -1;
    if (ike_header_decode(ike_pkt, ike_len, &hdr) != 0)
        return -1;

    sess_idx = ike_lb_session_lookup_spi(g_sessions, IKE_LB_MAX_SESSIONS,
                                         backend_idx, hdr.initiator_spi,
                                         hdr.responder_spi);
    if (sess_idx < 0 && !spi_is_zero(hdr.responder_spi)) {
        /* IKE_SA_INIT response: learn responder SPI */
        for (size_t i = 0; i < IKE_LB_MAX_SESSIONS; i++) {
            if (!g_sessions[i].in_use || g_sessions[i].backend_index != backend_idx)
                continue;
            if (memcmp(g_sessions[i].initiator_spi, hdr.initiator_spi, IKE_SPI_LEN) == 0) {
                ike_lb_session_set_responder_spi(g_sessions, IKE_LB_MAX_SESSIONS,
                                                 (int)i, hdr.responder_spi);
                sess_idx = (int)i;
                break;
            }
        }
    }
    if (sess_idx < 0)
        return -1;

    if (ike_lb_pcap_is_open())
        ike_lb_pcap_write(buf, len, cfg->backends[backend_idx].host,
                          cfg->backends[backend_idx].port, cfg->listen_host,
                          cfg->listen_port);

    ike_lb_session_touch(g_sessions, IKE_LB_MAX_SESSIONS, sess_idx);
    return relay_to_client(cfg, sess_idx, buf, len, cfg->listen_host, cfg->listen_port);
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

            peer_len = sizeof(peer);
            n = recvfrom(pf[i].fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&peer, &peer_len);
            if (n <= 0)
                continue;

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
                        if (handle_backend_packet(cfg, b, buf, (size_t)n) != 0)
                            fprintf(stderr, "drop %zd byte backend IKE packet\n", n);
                        break;
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
        cfg.backends[0].enabled = 1;
        strcpy(cfg.backends[1].host, "127.0.0.1");
        cfg.backends[1].port = 5002;
        cfg.backends[1].addr_len = sizeof(cfg.backends[1].addr);
        inet_pton(AF_INET, "127.0.0.1",
                  &((struct sockaddr_in *)&cfg.backends[1].addr)->sin_addr);
        ((struct sockaddr_in *)&cfg.backends[1].addr)->sin_family = AF_INET;
        ((struct sockaddr_in *)&cfg.backends[1].addr)->sin_port = htons(5002);
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
