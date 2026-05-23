#ifndef IKE_SESSION_H
#define IKE_SESSION_H

#include "ikev2_common.h"

#include <stddef.h>

struct ike_session {
    ike_spi_t initiator_spi;
    ike_spi_t responder_spi;
    uint32_t message_id;
    uint16_t dh_group;
    uint8_t *initiator_nonce;
    size_t initiator_nonce_len;
    uint8_t *responder_nonce;
    size_t responder_nonce_len;
    uint8_t *responder_ke;
    size_t responder_ke_len;
    uint8_t *responder_priv;
    size_t responder_priv_len;
    int established;
};

void ike_session_init(struct ike_session *s);
void ike_session_reset(struct ike_session *s);

int ike_handle_sa_init_request(const uint8_t *req, size_t req_len,
                               uint8_t *resp, size_t resp_cap,
                               size_t *resp_len, struct ike_session *session);

#endif /* IKE_SESSION_H */
