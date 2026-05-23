#include "ike_crypto.h"
#include "ike_msg.h"
#include "ike_session.h"
#include "ikev2_common.h"

#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_failed;

#define ASSERT(cond, msg)                          \
    do {                                           \
        tests_run++;                               \
        if (!(cond)) {                             \
            fprintf(stderr, "FAIL: %s\n", msg);  \
            tests_failed++;                        \
        }                                          \
    } while (0)

static void test_header_roundtrip(void)
{
    struct ike_header in, out;
    uint8_t buf[IKE_HEADER_LEN];
    size_t len;

    memset(&in, 0, sizeof(in));
    ike_spi_generate(in.initiator_spi);
    in.next_payload = IKE_PAYLOAD_SA;
    in.version = IKE_VERSION_BYTE;
    in.exchange_type = IKE_EXCHANGE_IKE_SA_INIT;
    in.flags = IKE_FLAG_INITIATOR;
    in.message_id = 42;
    in.length = IKE_HEADER_LEN;

    ASSERT(ike_header_encode(&in, buf, sizeof(buf), &len) == 0, "encode");
    ASSERT(len == IKE_HEADER_LEN, "encode length");
    ASSERT(ike_header_decode(buf, len, &out) == 0, "decode");
    ASSERT(memcmp(in.initiator_spi, out.initiator_spi, IKE_SPI_LEN) == 0,
           "spi match");
    ASSERT(out.message_id == 42, "message id");
}

static void test_sa_init_exchange(void)
{
    uint8_t req[4096], resp[4096];
    size_t req_len, resp_len;
    ike_spi_t init_spi;
    uint8_t *pub = NULL, *priv = NULL;
    size_t pub_len, priv_len;
    uint8_t nonce[IKE_NONCE_LEN];
    struct ike_session session;

    ike_spi_generate(init_spi);
    ASSERT(ike_dh_generate(IKE_DH_GROUP_14, &pub, &pub_len, &priv, &priv_len) == 0,
           "dh gen");
    ASSERT(ike_random_bytes(nonce, sizeof(nonce)) == 0, "nonce");

    ASSERT(ike_build_sa_init_request(req, sizeof(req), &req_len, init_spi, 0,
                                     IKE_DH_GROUP_14, pub, pub_len, nonce,
                                     sizeof(nonce)) == 0,
           "build request");

    ike_session_init(&session);
    ASSERT(ike_handle_sa_init_request(req, req_len, resp, sizeof(resp),
                                      &resp_len, &session) == 0,
           "handle request");
    ASSERT(session.established == 1, "session established");

    struct ike_parsed_msg parsed;
    ASSERT(ike_msg_parse(resp, resp_len, &parsed) == 0, "parse response");
    ASSERT(parsed.hdr.flags & IKE_FLAG_RESPONSE, "response flag");
    ASSERT(parsed.has_ke && parsed.has_nonce, "payloads present");
    ike_msg_free(&parsed);
    ike_session_reset(&session);
    ike_dh_free(pub, priv);
}

int main(void)
{
    test_header_roundtrip();
    test_sa_init_exchange();

    printf("Ran %d tests, %d failed\n", tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
