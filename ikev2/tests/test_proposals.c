#include "ike_crypto.h"
#include "ike_msg.h"
#include "ikev2_common.h"

#include <stdio.h>
#include <string.h>

static int tests_run, tests_failed;

#define ASSERT(c, m) \
    do { \
        tests_run++; \
        if (!(c)) { \
            fprintf(stderr, "FAIL: %s\n", m); \
            tests_failed++; \
        } \
    } while (0)

static void test_demo_sa_blob_present(void)
{
    uint8_t req[4096];
    size_t len;
    ike_spi_t spi;
    struct ike_parsed_msg parsed;

    memset(spi, 0xab, sizeof(spi));
    ASSERT(ike_build_sa_init_request(req, sizeof(req), &len, spi, 0,
                                     IKE_DH_GROUP_14, (uint8_t *)"KE", 2,
                                     (uint8_t *)"NONCE", 5) == 0,
           "build with SA");
    ASSERT(ike_msg_parse(req, len, &parsed) == 0, "parse");
    ASSERT(parsed.has_sa && parsed.sa_len > 20, "SA payload non-empty");
    /* Demo stub ends with DH group 14 (0x000e) per ike_msg.c */
    ASSERT(parsed.sa_len >= 4, "sa len");
    {
        int found_dh14 = 0;
        for (size_t i = 0; i + 1 < parsed.sa_len; i++) {
            if (parsed.sa_data[i] == 0x00 && parsed.sa_data[i + 1] == 0x0e) {
                found_dh14 = 1;
                break;
            }
        }
        ASSERT(found_dh14, "SA stub contains DH group 14 (0x000e)");
    }
    ike_msg_free(&parsed);
}

static void test_ike_sa_init_carries_sa_ke_nonce(void)
{
    uint8_t req[4096];
    size_t len;
    ike_spi_t spi;
    uint8_t *ke = NULL, *priv = NULL;
    size_t ke_len, priv_len;
    uint8_t nonce[32];
    struct ike_parsed_msg parsed;

    memset(spi, 0xab, sizeof(spi));
    ASSERT(ike_dh_generate(IKE_DH_GROUP_14, &ke, &ke_len, &priv, &priv_len) == 0,
           "dh");
    memset(nonce, 0xcd, sizeof(nonce));

    ASSERT(ike_build_sa_init_request(req, sizeof(req), &len, spi, 0,
                                     IKE_DH_GROUP_14, ke, ke_len, nonce,
                                     sizeof(nonce)) == 0,
           "build");
    ASSERT(ike_msg_parse(req, len, &parsed) == 0, "parse");
    ASSERT(parsed.has_sa && parsed.has_ke && parsed.has_nonce, "payloads");
    ASSERT(parsed.ke.dh_group == IKE_DH_GROUP_14, "KE group 14");
    ike_msg_free(&parsed);
    ike_dh_free(ke, priv);
}

int main(void)
{
    test_demo_sa_blob_present();
    test_ike_sa_init_carries_sa_ke_nonce();
    printf("Ran %d tests, %d failed\n", tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
