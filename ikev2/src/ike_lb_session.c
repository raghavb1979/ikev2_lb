#include "ike_lb.h"

#include "ike_msg.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t spi_hash(const ike_spi_t spi)
{
    uint32_t h = 0;
    for (int i = 0; i < IKE_SPI_LEN; i++)
        h = h * 31u + spi[i];
    return h;
}

static int spi_is_zero(const ike_spi_t spi)
{
    for (int i = 0; i < IKE_SPI_LEN; i++)
        if (spi[i] != 0)
            return 0;
    return 1;
}

int ike_lb_config_set_defaults(struct ike_lb_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->listen_host, "0.0.0.0", sizeof(cfg->listen_host) - 1);
    cfg->listen_port = 500;
    cfg->listen_natt_port = 4500;
    return 0;
}

int ike_lb_config_load(struct ike_lb_config *cfg, const char *path)
{
    FILE *f;
    char line[256];

    ike_lb_config_set_defaults(cfg);
    if (!path)
        return 0;

    f = fopen(path, "r");
    if (!f)
        return -1;

    while (fgets(line, sizeof(line), f)) {
        char key[64], val1[64];
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (sscanf(line, " listen %63s %hu", key, &cfg->listen_port) == 2) {
            strncpy(cfg->listen_host, key, sizeof(cfg->listen_host) - 1);
            continue;
        }
        if (sscanf(line, " natt_port %hu", &cfg->listen_natt_port) == 1)
            continue;
        if (strncmp(line, "backend", 7) == 0) {
            struct ike_lb_backend *b;
            unsigned bport = 500, bnatt = 4500;
            int has_natt = 0;
            if (cfg->num_backends >= IKE_LB_MAX_BACKENDS)
                continue;
            if (sscanf(line, " backend %63s %u natt %u", val1, &bport, &bnatt) >= 2)
                has_natt = (strstr(line, " natt ") != NULL);
            else if (sscanf(line, " backend %63s %u", val1, &bport) < 1)
                continue;
            b = &cfg->backends[cfg->num_backends++];
            strncpy(b->host, val1, sizeof(b->host) - 1);
            b->port = (uint16_t)bport;
            b->natt_port = has_natt ? (uint16_t)bnatt : b->port;
            b->addr_len = sizeof(b->addr);
            if (inet_pton(AF_INET, b->host, &((struct sockaddr_in *)&b->addr)->sin_addr) == 1) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&b->addr;
                struct sockaddr_in *snatt = (struct sockaddr_in *)&b->natt_addr;
                sin->sin_family = AF_INET;
                sin->sin_port = htons(b->port);
                memcpy(&b->natt_addr, &b->addr, sizeof(b->addr));
                snatt->sin_port = htons(b->natt_port);
                b->enabled = 1;
            }
        }
    }

    fclose(f);
    return cfg->num_backends > 0 ? 0 : -1;
}

int ike_lb_session_init(struct ike_lb_session *table, size_t capacity)
{
    memset(table, 0, sizeof(*table) * capacity);
    return 0;
}

void ike_lb_session_free(struct ike_lb_session *table)
{
    (void)table;
}

int ike_lb_pick_backend(const struct ike_lb_config *cfg, const ike_spi_t init_spi)
{
    int enabled[IKE_LB_MAX_BACKENDS];
    int n = 0;
    uint32_t h;

    if (cfg->num_backends <= 0)
        return -1;

    for (int i = 0; i < cfg->num_backends; i++) {
        if (cfg->backends[i].enabled) {
            enabled[n++] = i;
        }
    }
    if (n == 0)
        return -1;

    h = spi_hash(init_spi);
    return enabled[h % (uint32_t)n];
}

static int addr_match(const struct sockaddr_storage *a, socklen_t alen,
                      const struct sockaddr_storage *b, socklen_t blen)
{
    if (alen != blen)
        return 0;
    return memcmp(a, b, alen) == 0;
}

static int addr_ip_match(const struct sockaddr_storage *a, socklen_t alen,
                         const struct sockaddr_storage *b, socklen_t blen)
{
    const struct sockaddr_in *sa;
    const struct sockaddr_in *sb;

    if (alen < sizeof(struct sockaddr_in) || blen < sizeof(struct sockaddr_in))
        return 0;
    if (a->ss_family != AF_INET || b->ss_family != AF_INET)
        return 0;
    sa = (const struct sockaddr_in *)a;
    sb = (const struct sockaddr_in *)b;
    return sa->sin_addr.s_addr == sb->sin_addr.s_addr;
}

static int session_spi_match(const struct ike_lb_session *row,
                             const ike_spi_t init_spi, const ike_spi_t resp_spi)
{
    if (memcmp(row->initiator_spi, init_spi, IKE_SPI_LEN) != 0)
        return 0;
    if (!spi_is_zero(resp_spi) && !spi_is_zero(row->responder_spi) &&
        memcmp(row->responder_spi, resp_spi, IKE_SPI_LEN) != 0)
        return 0;
    return 1;
}

int ike_lb_session_lookup(struct ike_lb_session *table, size_t capacity,
                          const struct sockaddr_storage *client, socklen_t client_len,
                          const ike_spi_t init_spi, const ike_spi_t resp_spi)
{
    time_t now = time(NULL);
    int empty = -1;

    for (size_t i = 0; i < capacity; i++) {
        if (!table[i].in_use) {
            if (empty < 0)
                empty = (int)i;
            continue;
        }
        if (now - table[i].last_seen > IKE_LB_SESSION_TIMEOUT) {
            table[i].in_use = 0;
            if (empty < 0)
                empty = (int)i;
            continue;
        }
        if (!addr_match(&table[i].client_addr, table[i].client_len, client, client_len))
            continue;
        if (!session_spi_match(&table[i], init_spi, resp_spi))
            continue;
        return (int)i;
    }
    return -1;
}

int ike_lb_session_lookup_natt(struct ike_lb_session *table, size_t capacity,
                               const struct sockaddr_storage *client, socklen_t client_len,
                               const ike_spi_t init_spi, const ike_spi_t resp_spi)
{
    time_t now = time(NULL);

    if (spi_is_zero(resp_spi))
        return -1;

    for (size_t i = 0; i < capacity; i++) {
        if (!table[i].in_use)
            continue;
        if (now - table[i].last_seen > IKE_LB_SESSION_TIMEOUT) {
            table[i].in_use = 0;
            continue;
        }
        if (!addr_ip_match(&table[i].client_addr, table[i].client_len, client, client_len))
            continue;
        if (!session_spi_match(&table[i], init_spi, resp_spi))
            continue;
        return (int)i;
    }
    return -1;
}

void ike_lb_session_update_client(struct ike_lb_session *table, size_t capacity,
                                  int index, const struct sockaddr_storage *client,
                                  socklen_t client_len, int client_listen_fd)
{
    if (index < 0 || (size_t)index >= capacity || !table[index].in_use)
        return;
    memcpy(&table[index].client_addr, client, client_len);
    table[index].client_len = client_len;
    if (client_listen_fd >= 0)
        table[index].client_listen_fd = client_listen_fd;
    table[index].last_seen = time(NULL);
}

int ike_lb_session_lookup_client(struct ike_lb_session *table, size_t capacity,
                                 const struct sockaddr_storage *client, socklen_t client_len)
{
    time_t now = time(NULL);
    int best = -1;

    for (size_t i = 0; i < capacity; i++) {
        if (!table[i].in_use)
            continue;
        if (now - table[i].last_seen > IKE_LB_SESSION_TIMEOUT) {
            table[i].in_use = 0;
            continue;
        }
        if (!addr_match(&table[i].client_addr, table[i].client_len, client, client_len) &&
            !addr_ip_match(&table[i].client_addr, table[i].client_len, client, client_len))
            continue;
        if (best < 0 || table[i].last_seen >= table[best].last_seen)
            best = (int)i;
    }
    return best;
}

int ike_lb_session_lookup_single_backend(struct ike_lb_session *table, size_t capacity,
                                         int backend_index)
{
    time_t now = time(NULL);
    int only = -1;
    int count = 0;

    for (size_t i = 0; i < capacity; i++) {
        if (!table[i].in_use || table[i].backend_index != backend_index)
            continue;
        if (now - table[i].last_seen > IKE_LB_SESSION_TIMEOUT) {
            table[i].in_use = 0;
            continue;
        }
        count++;
        only = (int)i;
    }
    return (count == 1) ? only : -1;
}

int ike_lb_session_lookup_spi(struct ike_lb_session *table, size_t capacity,
                              int backend_index, const ike_spi_t init_spi,
                              const ike_spi_t resp_spi)
{
    time_t now = time(NULL);

    for (size_t i = 0; i < capacity; i++) {
        if (!table[i].in_use)
            continue;
        if (now - table[i].last_seen > IKE_LB_SESSION_TIMEOUT) {
            table[i].in_use = 0;
            continue;
        }
        if (table[i].backend_index != backend_index)
            continue;
        if (memcmp(table[i].initiator_spi, init_spi, IKE_SPI_LEN) != 0)
            continue;
        /* Responder SPI learned from first backend IKE_SA_INIT response. */
        if (!spi_is_zero(resp_spi) && !spi_is_zero(table[i].responder_spi) &&
            memcmp(table[i].responder_spi, resp_spi, IKE_SPI_LEN) != 0)
            continue;
        return (int)i;
    }
    return -1;
}

int ike_lb_session_bind(struct ike_lb_session *table, size_t capacity,
                        const struct sockaddr_storage *client, socklen_t client_len,
                        const ike_spi_t init_spi, int backend_index,
                        int client_listen_fd)
{
    time_t now = time(NULL);
    int slot = -1;

    for (size_t i = 0; i < capacity; i++) {
        if (!table[i].in_use) {
            slot = (int)i;
            break;
        }
        if (now - table[i].last_seen > IKE_LB_SESSION_TIMEOUT) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0)
        return -1;

    memset(&table[slot], 0, sizeof(table[slot]));
    memcpy(&table[slot].client_addr, client, client_len);
    table[slot].client_len = client_len;
    memcpy(table[slot].initiator_spi, init_spi, IKE_SPI_LEN);
    table[slot].backend_index = backend_index;
    table[slot].client_listen_fd = client_listen_fd;
    table[slot].last_seen = now;
    table[slot].in_use = 1;
    return slot;
}

void ike_lb_session_touch(struct ike_lb_session *table, size_t capacity, int index)
{
    if (index < 0 || (size_t)index >= capacity || !table[index].in_use)
        return;
    table[index].last_seen = time(NULL);
}

void ike_lb_session_set_responder_spi(struct ike_lb_session *table, size_t capacity,
                                      int index, const ike_spi_t resp_spi)
{
    if (index < 0 || (size_t)index >= capacity || !table[index].in_use)
        return;
    memcpy(table[index].responder_spi, resp_spi, IKE_SPI_LEN);
}
