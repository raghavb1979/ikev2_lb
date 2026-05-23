#ifndef IKE_CRYPTO_H
#define IKE_CRYPTO_H

#include "ikev2_common.h"

#include <stddef.h>
#include <stdint.h>

#define IKE_DH_GROUP_14 14
#define IKE_DH_GROUP_19 19

int ike_random_bytes(uint8_t *buf, size_t len);
void ike_spi_generate(ike_spi_t spi);

int ike_dh_generate(uint16_t group, uint8_t **pub_out, size_t *pub_len,
                    uint8_t **priv_out, size_t *priv_len);
void ike_dh_free(uint8_t *pub, uint8_t *priv);

#endif /* IKE_CRYPTO_H */
