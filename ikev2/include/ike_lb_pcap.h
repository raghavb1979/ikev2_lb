#ifndef IKE_LB_PCAP_H
#define IKE_LB_PCAP_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

int ike_lb_pcap_open(const char *path);
void ike_lb_pcap_close(void);
int ike_lb_pcap_is_open(void);

/* Record UDP datagram (IPv4 loopback-style addresses for lab) */
int ike_lb_pcap_write(const uint8_t *udp_payload, size_t payload_len,
                      const char *src_ip, uint16_t src_port,
                      const char *dst_ip, uint16_t dst_port);

#endif /* IKE_LB_PCAP_H */
