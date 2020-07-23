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

/* print Ethernet source MAC address */
void print_src_mac_addr(const Ethernet *eth) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->src_mac_addr[i]);
        if (i != 5) printf(":");
    }
}

/* print Ethernet destination MAC address */
void print_dst_mac_addr(const Ethernet *eth) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->dst_mac_addr[i]);
        if (i != 5) printf(":");
    }
}

/* print source IP address */
void print_src_ip_addr(const IPv4 *ip) {
    uint32_t addr = ntohl(ip->src_ip_addr);
    printf("%d.%d.%d.%d",
        (addr & 0xFF000000) >> 24,
        (addr & 0x00FF0000) >> 16,
        (addr & 0x0000FF00) >> 8,
        (addr & 0x000000FF)
    );
}

/* print destination IP address */
void print_dst_ip_addr(const IPv4 *ip) {
    uint32_t addr = ntohl(ip->dst_ip_addr);
    printf("%d.%d.%d.%d",
        (addr & 0xFF000000) >> 24,
        (addr & 0x00FF0000) >> 16,
        (addr & 0x0000FF00) >> 8,
        (addr & 0x000000FF)
    );
}

