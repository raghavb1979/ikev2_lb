#include "ike_session.h"
#include "ikev2_common.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RECV_BUF IKE_MAX_PACKET

static void print_spi(const char *label, const ike_spi_t spi)
{
    printf("%s ", label);
    for (int i = 0; i < IKE_SPI_LEN; i++)
        printf("%02x", spi[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *bind_addr = "0.0.0.0";
    uint16_t port = IKE_UDP_PORT;
    int fd;
    struct sockaddr_in addr, peer;
    socklen_t peer_len = sizeof(peer);
    uint8_t recv_buf[RECV_BUF];
    uint8_t send_buf[RECV_BUF];
    struct ike_session session;

    if (argc > 1)
        bind_addr = argv[1];
    if (argc > 2)
        port = (uint16_t)atoi(argv[2]);
    else
        port = 5000; /* non-root friendly default; use argv[2]=500 with cap_net */

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid bind address: %s\n", bind_addr);
        close(fd);
        return 1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }

    printf("IKEv2 server listening on %s:%u (UDP)\n", bind_addr, port);
    ike_session_init(&session);

    for (;;) {
        ssize_t n = recvfrom(fd, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        printf("\nReceived %zd bytes from %s:%d\n", n,
               inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

        size_t resp_len = 0;
        if (ike_handle_sa_init_request(recv_buf, (size_t)n, send_buf,
                                        sizeof(send_buf), &resp_len,
                                        &session) != 0) {
            fprintf(stderr, "failed to handle IKE_SA_INIT request\n");
            continue;
        }

        ssize_t sent = sendto(fd, send_buf, resp_len, 0,
                              (struct sockaddr *)&peer, peer_len);
        if (sent < 0) {
            perror("sendto");
            continue;
        }

        printf("Sent IKE_SA_INIT response (%zd bytes)\n", sent);
        print_spi("Initiator SPI:", session.initiator_spi);
        print_spi("Responder SPI:", session.responder_spi);
        printf("DH group: %u, session established: %d\n", session.dh_group,
               session.established);
    }

    ike_session_reset(&session);
    close(fd);
    return 0;
}
