#include "ike_crypto.h"
#include "ike_msg.h"
#include "ikev2_common.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define IO_BUF IKE_MAX_PACKET

static void print_spi(const char *label, const ike_spi_t spi)
{
    printf("%s ", label);
    for (int i = 0; i < IKE_SPI_LEN; i++)
        printf("%02x", spi[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *server_host = "127.0.0.1";
    uint16_t port = 5000;
    int fd;
    struct sockaddr_in peer;
    uint8_t req[IO_BUF];
    uint8_t resp[IO_BUF];
    size_t req_len;
    ssize_t n;
    ike_spi_t initiator_spi;
    uint8_t *ke_pub = NULL;
    uint8_t *ke_priv = NULL;
    size_t ke_pub_len = 0;
    size_t ke_priv_len = 0;
    uint8_t nonce[IKE_NONCE_LEN];
    struct ike_parsed_msg parsed;

    if (argc > 1)
        server_host = argv[1];
    if (argc > 2)
        port = (uint16_t)atoi(argv[2]);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(port);
    if (inet_pton(AF_INET, server_host, &peer.sin_addr) != 1) {
        fprintf(stderr, "invalid server address: %s\n", server_host);
        close(fd);
        return 1;
    }

    ike_spi_generate(initiator_spi);
    if (ike_dh_generate(IKE_DH_GROUP_14, &ke_pub, &ke_pub_len, &ke_priv,
                          &ke_priv_len) != 0) {
        fprintf(stderr, "DH key generation failed\n");
        close(fd);
        return 1;
    }
    if (ike_random_bytes(nonce, sizeof(nonce)) != 0) {
        fprintf(stderr, "nonce generation failed\n");
        ike_dh_free(ke_pub, ke_priv);
        close(fd);
        return 1;
    }

    if (ike_build_sa_init_request(req, sizeof(req), &req_len, initiator_spi, 0,
                                  IKE_DH_GROUP_14, ke_pub, ke_pub_len, nonce,
                                  sizeof(nonce)) != 0) {
        fprintf(stderr, "failed to build IKE_SA_INIT request\n");
        ike_dh_free(ke_pub, ke_priv);
        close(fd);
        return 1;
    }

    printf("Sending IKE_SA_INIT request (%zu bytes) to %s:%u\n", req_len,
           server_host, port);
    print_spi("Initiator SPI:", initiator_spi);

    n = sendto(fd, req, req_len, 0, (struct sockaddr *)&peer, sizeof(peer));
    if (n < 0) {
        perror("sendto");
        ike_dh_free(ke_pub, ke_priv);
        close(fd);
        return 1;
    }

    n = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
    if (n < 0) {
        perror("recvfrom");
        ike_dh_free(ke_pub, ke_priv);
        close(fd);
        return 1;
    }

    printf("Received response (%zd bytes)\n", n);

    if (ike_msg_parse(resp, (size_t)n, &parsed) != 0) {
        fprintf(stderr, "failed to parse response\n");
        ike_dh_free(ke_pub, ke_priv);
        close(fd);
        return 1;
    }

    if (!(parsed.hdr.flags & IKE_FLAG_RESPONSE) ||
        parsed.hdr.exchange_type != IKE_EXCHANGE_IKE_SA_INIT) {
        fprintf(stderr, "unexpected response message\n");
        ike_msg_free(&parsed);
        ike_dh_free(ke_pub, ke_priv);
        close(fd);
        return 1;
    }

    print_spi("Responder SPI:", parsed.hdr.responder_spi);
    printf("Response has SA=%d KE=%d Nonce=%d\n", parsed.has_sa, parsed.has_ke,
           parsed.has_nonce);

    ike_msg_free(&parsed);
    ike_dh_free(ke_pub, ke_priv);
    close(fd);
    printf("IKE_SA_INIT exchange completed successfully.\n");
    return 0;
}
