#include "ike_lb_pcap.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define PCAP_LINKTYPE_RAW 12 /* DLT_RAW — IPv4 packet */
#define ETH_IP_HDR_LEN 20
#define UDP_HDR_LEN 8

static FILE *g_pcap;

int ike_lb_pcap_open(const char *path)
{
    struct {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t tz;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    } gh = {
        0xa1b2c3d4, 2, 4, 0, 0, 65535, PCAP_LINKTYPE_RAW,
    };

    if (g_pcap)
        fclose(g_pcap);
    g_pcap = fopen(path, "wb");
    if (!g_pcap)
        return -1;
    if (fwrite(&gh, sizeof(gh), 1, g_pcap) != 1) {
        fclose(g_pcap);
        g_pcap = NULL;
        return -1;
    }
    return 0;
}

void ike_lb_pcap_close(void)
{
    if (g_pcap) {
        fclose(g_pcap);
        g_pcap = NULL;
    }
}

int ike_lb_pcap_is_open(void)
{
    return g_pcap != NULL;
}

int ike_lb_pcap_write(const uint8_t *udp_payload, size_t payload_len,
                      const char *src_ip, uint16_t src_port,
                      const char *dst_ip, uint16_t dst_port)
{
    uint8_t frame[2048];
    size_t ip_len, udp_len, frame_len;
    struct timeval tv;
    uint32_t sec, usec;
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } ph;
    uint16_t tot_len;
    struct in_addr src_a, dst_a;

    if (!g_pcap || payload_len > sizeof(frame) - 64)
        return -1;
    if (inet_pton(AF_INET, src_ip, &src_a) != 1 || inet_pton(AF_INET, dst_ip, &dst_a) != 1)
        return -1;

    gettimeofday(&tv, NULL);
    sec = (uint32_t)tv.tv_sec;
    usec = (uint32_t)tv.tv_usec;

    udp_len = UDP_HDR_LEN + payload_len;
    tot_len = (uint16_t)(ETH_IP_HDR_LEN + udp_len);
    ip_len = tot_len;
    frame_len = ip_len;

    memset(frame, 0, sizeof(frame));
    frame[0] = 0x45;
    frame[1] = 0x00;
    frame[2] = (uint8_t)(tot_len >> 8);
    frame[3] = (uint8_t)(tot_len & 0xff);
    frame[8] = 64;
    frame[9] = 17; /* UDP */
    memcpy(frame + 12, &src_a, 4);
    memcpy(frame + 16, &dst_a, 4);

    frame[ETH_IP_HDR_LEN] = (uint8_t)(src_port >> 8);
    frame[ETH_IP_HDR_LEN + 1] = (uint8_t)(src_port & 0xff);
    frame[ETH_IP_HDR_LEN + 2] = (uint8_t)(dst_port >> 8);
    frame[ETH_IP_HDR_LEN + 3] = (uint8_t)(dst_port & 0xff);
    frame[ETH_IP_HDR_LEN + 4] = (uint8_t)(udp_len >> 8);
    frame[ETH_IP_HDR_LEN + 5] = (uint8_t)(udp_len & 0xff);
    memcpy(frame + ETH_IP_HDR_LEN + UDP_HDR_LEN, udp_payload, payload_len);

    ph.ts_sec = sec;
    ph.ts_usec = usec;
    ph.incl_len = (uint32_t)frame_len;
    ph.orig_len = (uint32_t)frame_len;

    if (fwrite(&ph, sizeof(ph), 1, g_pcap) != 1)
        return -1;
    if (fwrite(frame, frame_len, 1, g_pcap) != 1)
        return -1;
    fflush(g_pcap);
    return 0;
}
