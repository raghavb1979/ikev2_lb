#ifndef IKE_LB_H
#define IKE_LB_H

#include "ikev2_common.h"

#include <netinet/in.h>
#include <stddef.h>
#include <time.h>

/* Override at build time: make IKE_LB_MAX_SESSIONS=8192 ... */
#ifndef IKE_LB_MAX_BACKENDS
#define IKE_LB_MAX_BACKENDS 32
#endif
#ifndef IKE_LB_MAX_SESSIONS
#define IKE_LB_MAX_SESSIONS 65536
#endif
#ifndef IKE_LB_SESSION_TIMEOUT
#define IKE_LB_SESSION_TIMEOUT 3600
#endif

struct ike_lb_backend {
    char host[64];
    uint16_t port;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int enabled;
};

struct ike_lb_config {
    struct ike_lb_backend backends[IKE_LB_MAX_BACKENDS];
    int num_backends;
    char listen_host[64];
    uint16_t listen_port;
    uint16_t listen_natt_port;
};

struct ike_lb_session {
    struct sockaddr_storage client_addr;
    socklen_t client_len;
    ike_spi_t initiator_spi;
    ike_spi_t responder_spi;
    int backend_index;
    int client_listen_fd;
    time_t last_seen;
    int in_use;
};

int ike_lb_config_load(struct ike_lb_config *cfg, const char *path);
int ike_lb_config_set_defaults(struct ike_lb_config *cfg);

int ike_lb_session_init(struct ike_lb_session *table, size_t capacity);
void ike_lb_session_free(struct ike_lb_session *table);

int ike_lb_pick_backend(const struct ike_lb_config *cfg, const ike_spi_t init_spi);
int ike_lb_session_lookup(struct ike_lb_session *table, size_t capacity,
                          const struct sockaddr_storage *client, socklen_t client_len,
                          const ike_spi_t init_spi, const ike_spi_t resp_spi);
int ike_lb_session_bind(struct ike_lb_session *table, size_t capacity,
                        const struct sockaddr_storage *client, socklen_t client_len,
                        const ike_spi_t init_spi, int backend_index,
                        int client_listen_fd);
int ike_lb_session_lookup_spi(struct ike_lb_session *table, size_t capacity,
                              int backend_index, const ike_spi_t init_spi,
                              const ike_spi_t resp_spi);
void ike_lb_session_touch(struct ike_lb_session *table, size_t capacity, int index);
void ike_lb_session_set_responder_spi(struct ike_lb_session *table, size_t capacity,
                                      int index, const ike_spi_t resp_spi);

#endif /* IKE_LB_H */
