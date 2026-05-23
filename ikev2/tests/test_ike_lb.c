#include "ike_lb.h"
#include "ike_crypto.h"

#include <arpa/inet.h>
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

static void sockaddr_in4(struct sockaddr_storage *ss, socklen_t *len,
                         const char *ip, uint16_t port)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    memset(ss, 0, sizeof(*ss));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    inet_pton(AF_INET, ip, &sin->sin_addr);
    *len = sizeof(*sin);
}

static void test_backend_pick_stable(void)
{
    struct ike_lb_config cfg;
    ike_spi_t spi;

    memset(&cfg, 0, sizeof(cfg));
    cfg.num_backends = 3;
    for (int i = 0; i < 3; i++)
        cfg.backends[i].enabled = 1;

    ike_spi_generate(spi);
    int b1 = ike_lb_pick_backend(&cfg, spi);
    int b2 = ike_lb_pick_backend(&cfg, spi);
    ASSERT(b1 >= 0 && b1 == b2, "same SPI maps to same backend");
}

static void test_session_bind_lookup(void)
{
    struct ike_lb_session table[16];
    struct sockaddr_storage c1, c2;
    socklen_t l1, l2;
    ike_spi_t spi1, spi2;
    ike_spi_t zero = {0};

    ike_lb_session_init(table, 16);
    sockaddr_in4(&c1, &l1, "10.1.0.5", 4500);
    sockaddr_in4(&c2, &l2, "10.1.0.6", 4500);
    ike_spi_generate(spi1);
    ike_spi_generate(spi2);

    ASSERT(ike_lb_session_bind(table, 16, &c1, l1, spi1, 0, 10) >= 0, "bind c1");
    ASSERT(ike_lb_session_bind(table, 16, &c2, l2, spi2, 1, 10) >= 0, "bind c2");

    ASSERT(ike_lb_session_lookup(table, 16, &c1, l1, spi1, zero) >= 0,
           "lookup c1 by client+spi");
    ASSERT(ike_lb_session_lookup(table, 16, &c2, l2, spi2, zero) >= 0,
           "lookup c2 by client+spi");
    ASSERT(ike_lb_session_lookup_spi(table, 16, 0, spi1, zero) >= 0,
           "lookup_spi backend 0");
}

static void test_config_load(void)
{
    struct ike_lb_config cfg;
    if (ike_lb_config_load(&cfg, "config/ike-lb.conf") == 0) {
        ASSERT(cfg.num_backends >= 2, "lab config has backends");
    } else {
        ASSERT(ike_lb_config_set_defaults(&cfg) == 0, "defaults ok");
    }
}

int main(void)
{
    test_backend_pick_stable();
    test_session_bind_lookup();
    test_config_load();
    printf("Ran %d tests, %d failed\n", tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
