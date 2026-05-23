#include "ike_crypto.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef IKEV2_NO_SSL
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#endif

static int read_urandom(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t n;
    if (fd < 0)
        return -1;
    n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

int ike_random_bytes(uint8_t *buf, size_t len)
{
#ifndef IKEV2_NO_SSL
    if (RAND_bytes(buf, (int)len) == 1)
        return 0;
#endif
    return read_urandom(buf, len);
}

void ike_spi_generate(ike_spi_t spi)
{
    if (ike_random_bytes(spi, IKE_SPI_LEN) != 0) {
        for (size_t i = 0; i < IKE_SPI_LEN; i++)
            spi[i] = (uint8_t)(rand() & 0xff);
    }
}

#ifndef IKEV2_NO_SSL

static DH *dh_new_group(uint16_t group)
{
    switch (group) {
    case IKE_DH_GROUP_14:
        return DH_get_2048_256();
    default:
        return DH_get_2048_256();
    }
}

int ike_dh_generate(uint16_t group, uint8_t **pub_out, size_t *pub_len,
                    uint8_t **priv_out, size_t *priv_len)
{
    DH *dh = NULL;
    const BIGNUM *pub_bn = NULL;
    const BIGNUM *priv_bn = NULL;
    int pub_bytes;
    int priv_bytes;

    if (!pub_out || !pub_len || !priv_out || !priv_len)
        return -1;

    *pub_out = NULL;
    *priv_out = NULL;

    dh = dh_new_group(group);
    if (!dh)
        return -1;
    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        return -1;
    }

    DH_get0_key(dh, &pub_bn, &priv_bn);
    pub_bytes = BN_num_bytes(pub_bn);
    priv_bytes = BN_num_bytes(priv_bn);

    *pub_out = malloc((size_t)pub_bytes);
    *priv_out = malloc((size_t)priv_bytes);
    if (!*pub_out || !*priv_out) {
        free(*pub_out);
        free(*priv_out);
        DH_free(dh);
        return -1;
    }

    BN_bn2bin(pub_bn, *pub_out);
    BN_bn2bin(priv_bn, *priv_out);
    *pub_len = (size_t)pub_bytes;
    *priv_len = (size_t)priv_bytes;

    DH_free(dh);
    return 0;
}

#else /* IKEV2_NO_SSL: stub KE material for message-flow testing only */

#define IKE_STUB_KE_LEN 256

int ike_dh_generate(uint16_t group, uint8_t **pub_out, size_t *pub_len,
                    uint8_t **priv_out, size_t *priv_len)
{
    (void)group;
    *pub_out = malloc(IKE_STUB_KE_LEN);
    *priv_out = malloc(IKE_STUB_KE_LEN);
    if (!*pub_out || !*priv_out) {
        free(*pub_out);
        free(*priv_out);
        return -1;
    }
    if (ike_random_bytes(*pub_out, IKE_STUB_KE_LEN) != 0 ||
        ike_random_bytes(*priv_out, IKE_STUB_KE_LEN) != 0) {
        free(*pub_out);
        free(*priv_out);
        return -1;
    }
    *pub_len = IKE_STUB_KE_LEN;
    *priv_len = IKE_STUB_KE_LEN;
    return 0;
}

#endif

void ike_dh_free(uint8_t *pub, uint8_t *priv)
{
    free(pub);
    free(priv);
}
