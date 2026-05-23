#ifndef IKEV2_COMMON_H
#define IKEV2_COMMON_H

#include <stddef.h>
#include <stdint.h>

#define IKE_VERSION_MAJOR 2
#define IKE_VERSION_MINOR 0
#define IKE_VERSION_BYTE ((IKE_VERSION_MAJOR << 4) | IKE_VERSION_MINOR)

#define IKE_HEADER_LEN 28
#define IKE_PAYLOAD_HEADER_LEN 4
#define IKE_SPI_LEN 8
#define IKE_NONCE_MIN_LEN 16
#define IKE_NONCE_LEN 32
#define IKE_MAX_PACKET 65535
#define IKE_UDP_PORT 500

/* Exchange types (RFC 7296) */
#define IKE_EXCHANGE_IKE_SA_INIT 34
#define IKE_EXCHANGE_IKE_AUTH 35

/* Payload types */
#define IKE_PAYLOAD_NONE 0
#define IKE_PAYLOAD_SA 33
#define IKE_PAYLOAD_KE 34
#define IKE_PAYLOAD_NONCE 40
#define IKE_PAYLOAD_NOTIFY 41

/* Flags */
#define IKE_FLAG_INITIATOR 0x08
#define IKE_FLAG_RESPONSE 0x20

/* Notify types */
#define IKE_NOTIFY_INVALID_IKE_SPI 7
#define IKE_NOTIFY_INVALID_MAJOR_VERSION 11

typedef uint8_t ike_spi_t[IKE_SPI_LEN];

struct ike_header {
    ike_spi_t initiator_spi;
    ike_spi_t responder_spi;
    uint8_t next_payload;
    uint8_t version;
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
};

#endif /* IKEV2_COMMON_H */
