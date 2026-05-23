#include "ike_session.h"

#include "ike_crypto.h"
#include "ike_msg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ike_session_init(struct ike_session *s)
{
    memset(s, 0, sizeof(*s));
}

void ike_session_reset(struct ike_session *s)
{
    if (!s)
        return;
    free(s->initiator_nonce);
    free(s->responder_nonce);
    free(s->responder_ke);
    free(s->responder_priv);
    ike_session_init(s);
}

int ike_handle_sa_init_request(const uint8_t *req, size_t req_len,
                               uint8_t *resp, size_t resp_cap,
                               size_t *resp_len, struct ike_session *session)
{
    struct ike_parsed_msg parsed;
    int rc = -1;

    if (ike_msg_parse(req, req_len, &parsed) != 0)
        return -1;

    if (parsed.hdr.version != IKE_VERSION_BYTE) {
        ike_msg_free(&parsed);
        return -1;
    }
    if (parsed.hdr.exchange_type != IKE_EXCHANGE_IKE_SA_INIT) {
        ike_msg_free(&parsed);
        return -1;
    }
    if (!(parsed.hdr.flags & IKE_FLAG_INITIATOR)) {
        ike_msg_free(&parsed);
        return -1;
    }
    if (!parsed.has_ke || !parsed.has_nonce) {
        ike_msg_free(&parsed);
        return -1;
    }

    ike_session_reset(session);
    memcpy(session->initiator_spi, parsed.hdr.initiator_spi, IKE_SPI_LEN);
    ike_spi_generate(session->responder_spi);
    session->message_id = parsed.hdr.message_id;
    session->dh_group = parsed.ke.dh_group;

    session->initiator_nonce_len = parsed.nonce.nonce_len;
    session->initiator_nonce = malloc(session->initiator_nonce_len);
    if (!session->initiator_nonce)
        goto cleanup;
    memcpy(session->initiator_nonce, parsed.nonce.nonce_data,
           session->initiator_nonce_len);

    if (ike_dh_generate(session->dh_group, &session->responder_ke,
                        &session->responder_ke_len, &session->responder_priv,
                        &session->responder_priv_len) != 0)
        goto cleanup;

    session->responder_nonce_len = IKE_NONCE_LEN;
    session->responder_nonce = malloc(session->responder_nonce_len);
    if (!session->responder_nonce)
        goto cleanup;
    if (ike_random_bytes(session->responder_nonce, session->responder_nonce_len) != 0)
        goto cleanup;

    if (ike_build_sa_init_response(resp, resp_cap, resp_len, &parsed.hdr,
                                   session->responder_spi, session->dh_group,
                                   session->responder_ke, session->responder_ke_len,
                                   session->responder_nonce,
                                   session->responder_nonce_len) != 0)
        goto cleanup;

    session->established = 1;
    rc = 0;

cleanup:
    ike_msg_free(&parsed);
    if (rc != 0)
        ike_session_reset(session);
    return rc;
}
