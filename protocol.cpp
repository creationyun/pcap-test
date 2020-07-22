#include <pcap.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include "protocol.h"

/* get IP version */
uint8_t get_ip_version(const IPv4 *ip) {
    return (ip->ver_hdrlen) >> 4;
}

/* get IP header length as byte */
uint8_t get_ip_hdrlen(const IPv4 *ip) {
    return ((ip->ver_hdrlen) & 0x0f) * 4;
}

/* get TCP header length */
uint8_t get_tcp_hdrlen(const TCP *tcp) {
    return (uint8_t)(ntohs(tcp->hdrlen_flags) >> 12) * 4;
}

