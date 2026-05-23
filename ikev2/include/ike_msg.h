#ifndef IKE_MSG_H
#define IKE_MSG_H

#include "ikev2_common.h"

#include <stddef.h>

struct ike_ke_payload {
    uint16_t dh_group;
    uint8_t *ke_data;
    size_t ke_len;
};

struct ike_nonce_payload {
    uint8_t *nonce_data;
    size_t nonce_len;
};

struct ike_parsed_msg {
    struct ike_header hdr;
    uint8_t *sa_data;
    size_t sa_len;
    struct ike_ke_payload ke;
    struct ike_nonce_payload nonce;
    int has_sa;
    int has_ke;
    int has_nonce;
};

int ike_header_encode(const struct ike_header *hdr, uint8_t *buf, size_t cap,
                      size_t *out_len);
int ike_header_decode(const uint8_t *buf, size_t len, struct ike_header *hdr);

int ike_msg_parse(const uint8_t *buf, size_t len, struct ike_parsed_msg *out);
void ike_msg_free(struct ike_parsed_msg *msg);

int ike_build_sa_init_request(uint8_t *buf, size_t cap, size_t *out_len,
                              const ike_spi_t initiator_spi,
                              uint32_t message_id, uint16_t dh_group,
                              const uint8_t *ke, size_t ke_len,
                              const uint8_t *nonce, size_t nonce_len);

int ike_build_sa_init_response(uint8_t *buf, size_t cap, size_t *out_len,
                               const struct ike_header *req_hdr,
                               const ike_spi_t responder_spi, uint16_t dh_group,
                               const uint8_t *ke, size_t ke_len,
                               const uint8_t *nonce, size_t nonce_len);

#endif /* IKE_MSG_H */
