#include "ike_msg.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static uint32_t read_u32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return ntohl(v);
}

static void write_u32(uint8_t *p, uint32_t v)
{
    uint32_t n = htonl(v);
    memcpy(p, &n, 4);
}

static uint16_t read_u16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return ntohs(v);
}

static void write_u16(uint8_t *p, uint16_t v)
{
    uint16_t n = htons(v);
    memcpy(p, &n, 2);
}

int ike_header_encode(const struct ike_header *hdr, uint8_t *buf, size_t cap,
                      size_t *out_len)
{
    if (cap < IKE_HEADER_LEN)
        return -1;

    memcpy(buf, hdr->initiator_spi, IKE_SPI_LEN);
    memcpy(buf + 8, hdr->responder_spi, IKE_SPI_LEN);
    buf[16] = hdr->next_payload;
    buf[17] = hdr->version;
    buf[18] = hdr->exchange_type;
    buf[19] = hdr->flags;
    write_u32(buf + 20, hdr->message_id);
    write_u32(buf + 24, hdr->length);

    if (out_len)
        *out_len = IKE_HEADER_LEN;
    return 0;
}

int ike_header_decode(const uint8_t *buf, size_t len, struct ike_header *hdr)
{
    if (len < IKE_HEADER_LEN)
        return -1;

    memcpy(hdr->initiator_spi, buf, IKE_SPI_LEN);
    memcpy(hdr->responder_spi, buf + 8, IKE_SPI_LEN);
    hdr->next_payload = buf[16];
    hdr->version = buf[17];
    hdr->exchange_type = buf[18];
    hdr->flags = buf[19];
    hdr->message_id = read_u32(buf + 20);
    hdr->length = read_u32(buf + 24);
    return 0;
}

static int parse_payload_chain(const uint8_t *buf, size_t total_len,
                               struct ike_parsed_msg *out)
{
    size_t offset = IKE_HEADER_LEN;
    uint8_t next = out->hdr.next_payload;

    while (next != IKE_PAYLOAD_NONE && offset + IKE_PAYLOAD_HEADER_LEN <= total_len) {
        uint8_t payload_next = buf[offset];
        uint16_t payload_len = read_u16(buf + offset + 2);

        if (payload_len < IKE_PAYLOAD_HEADER_LEN ||
            offset + payload_len > total_len)
            return -1;

        const uint8_t *body = buf + offset + IKE_PAYLOAD_HEADER_LEN;
        size_t body_len = payload_len - IKE_PAYLOAD_HEADER_LEN;

        switch (next) {
        case IKE_PAYLOAD_SA:
            out->sa_data = malloc(body_len);
            if (!out->sa_data)
                return -1;
            memcpy(out->sa_data, body, body_len);
            out->sa_len = body_len;
            out->has_sa = 1;
            break;
        case IKE_PAYLOAD_KE:
            if (body_len < 4)
                return -1;
            out->ke.dh_group = read_u16(body);
            out->ke.ke_len = body_len - 4;
            out->ke.ke_data = malloc(out->ke.ke_len);
            if (!out->ke.ke_data)
                return -1;
            memcpy(out->ke.ke_data, body + 4, out->ke.ke_len);
            out->has_ke = 1;
            break;
        case IKE_PAYLOAD_NONCE:
            out->nonce.nonce_len = body_len;
            out->nonce.nonce_data = malloc(body_len);
            if (!out->nonce.nonce_data)
                return -1;
            memcpy(out->nonce.nonce_data, body, body_len);
            out->has_nonce = 1;
            break;
        default:
            break;
        }

        next = payload_next;
        offset += payload_len;
    }

    return 0;
}

int ike_msg_parse(const uint8_t *buf, size_t len, struct ike_parsed_msg *out)
{
    memset(out, 0, sizeof(*out));

    if (ike_header_decode(buf, len, &out->hdr) != 0)
        return -1;
    if (out->hdr.length > len || out->hdr.length < IKE_HEADER_LEN)
        return -1;

    return parse_payload_chain(buf, out->hdr.length, out);
}

void ike_msg_free(struct ike_parsed_msg *msg)
{
    if (!msg)
        return;
    free(msg->sa_data);
    free(msg->ke.ke_data);
    free(msg->nonce.nonce_data);
    memset(msg, 0, sizeof(*msg));
}

/* Minimal SA proposal: one proposal with AES-GCM + PRF + DH (stub bytes). */
static size_t append_minimal_sa(uint8_t *buf, size_t offset, size_t cap)
{
    /* Simplified proposal blob for demo; real IKE needs full transforms. */
    static const uint8_t sa_stub[] = {
        0x00, 0x00, 0x00, 0x20, /* proposals length placeholder */
        0x01, 0x01, 0x00, 0x03, /* 1 proposal, proto IKE, SPI size 0, num transforms 3 */
        0x03, 0x00, 0x00, 0x0c, /* transform ENCR */
        0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x0c, /* AES-GCM-16 */
        0x03, 0x00, 0x00, 0x08, /* transform PRF */
        0x02, 0x00, 0x00, 0x05, /* HMAC-SHA2-256 */
        0x03, 0x00, 0x00, 0x08, /* transform DH */
        0x04, 0x00, 0x00, 0x0e  /* group 14 */
    };

    if (offset + sizeof(sa_stub) > cap)
        return 0;
    memcpy(buf + offset, sa_stub, sizeof(sa_stub));
    return offset + sizeof(sa_stub);
}

static size_t append_payload(uint8_t *buf, size_t offset, size_t cap,
                             uint8_t next, const uint8_t *body, size_t body_len)
{
    uint16_t plen = (uint16_t)(IKE_PAYLOAD_HEADER_LEN + body_len);
    if (offset + plen > cap)
        return 0;

    buf[offset] = next;
    buf[offset + 1] = 0;
    write_u16(buf + offset + 2, plen);
    if (body_len > 0)
        memcpy(buf + offset + IKE_PAYLOAD_HEADER_LEN, body, body_len);
    return offset + plen;
}

int ike_build_sa_init_request(uint8_t *buf, size_t cap, size_t *out_len,
                              const ike_spi_t initiator_spi,
                              uint32_t message_id, uint16_t dh_group,
                              const uint8_t *ke, size_t ke_len,
                              const uint8_t *nonce, size_t nonce_len)
{
    size_t offset = IKE_HEADER_LEN;
    uint8_t ke_body[4096];
    size_t ke_body_len;
    uint8_t sa_body[128];
    size_t sa_body_len;

    if (ke_len + 4 > sizeof(ke_body) || nonce_len == 0)
        return -1;

    write_u16(ke_body, dh_group);
    write_u16(ke_body + 2, 0);
    memcpy(ke_body + 4, ke, ke_len);
    ke_body_len = 4 + ke_len;

    sa_body_len = append_minimal_sa(sa_body, 0, sizeof(sa_body));
    if (sa_body_len == 0)
        return -1;

    offset = append_payload(buf, offset, cap, IKE_PAYLOAD_KE, sa_body, sa_body_len);
    if (offset == 0)
        return -1;

    offset = append_payload(buf, offset, cap, IKE_PAYLOAD_NONCE, ke_body, ke_body_len);
    if (offset == 0)
        return -1;

    offset = append_payload(buf, offset, cap, IKE_PAYLOAD_NONE, nonce, nonce_len);
    if (offset == 0)
        return -1;

    struct ike_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.initiator_spi, initiator_spi, IKE_SPI_LEN);
    hdr.next_payload = IKE_PAYLOAD_SA;
    hdr.version = IKE_VERSION_BYTE;
    hdr.exchange_type = IKE_EXCHANGE_IKE_SA_INIT;
    hdr.flags = IKE_FLAG_INITIATOR;
    hdr.message_id = message_id;
    hdr.length = (uint32_t)offset;

    if (ike_header_encode(&hdr, buf, cap, NULL) != 0)
        return -1;

    if (out_len)
        *out_len = offset;
    return 0;
}

int ike_build_sa_init_response(uint8_t *buf, size_t cap, size_t *out_len,
                               const struct ike_header *req_hdr,
                               const ike_spi_t responder_spi, uint16_t dh_group,
                               const uint8_t *ke, size_t ke_len,
                               const uint8_t *nonce, size_t nonce_len)
{
    size_t offset = IKE_HEADER_LEN;
    uint8_t ke_body[4096];
    size_t ke_body_len;
    uint8_t sa_pl[128];
    size_t sa_off;

    if (ke_len + 4 > sizeof(ke_body) || nonce_len == 0)
        return -1;

    write_u16(ke_body, dh_group);
    write_u16(ke_body + 2, 0);
    memcpy(ke_body + 4, ke, ke_len);
    ke_body_len = 4 + ke_len;

    sa_off = append_minimal_sa(sa_pl, 0, sizeof(sa_pl));
    if (sa_off == 0)
        return -1;

    offset = append_payload(buf, offset, cap, IKE_PAYLOAD_KE, sa_pl, sa_off);
    if (offset == 0)
        return -1;

    offset = append_payload(buf, offset, cap, IKE_PAYLOAD_NONCE, ke_body, ke_body_len);
    if (offset == 0)
        return -1;

    offset = append_payload(buf, offset, cap, IKE_PAYLOAD_NONE, nonce, nonce_len);
    if (offset == 0)
        return -1;

    struct ike_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.initiator_spi, req_hdr->initiator_spi, IKE_SPI_LEN);
    memcpy(hdr.responder_spi, responder_spi, IKE_SPI_LEN);
    hdr.next_payload = IKE_PAYLOAD_SA;
    hdr.version = IKE_VERSION_BYTE;
    hdr.exchange_type = IKE_EXCHANGE_IKE_SA_INIT;
    hdr.flags = IKE_FLAG_RESPONSE;
    hdr.message_id = req_hdr->message_id;
    hdr.length = (uint32_t)offset;

    if (ike_header_encode(&hdr, buf, cap, NULL) != 0)
        return -1;

    if (out_len)
        *out_len = offset;
    return 0;
}
