// protocol.h: Network protocol structures for capturing network packet
// Created by Creation Yun

/* Constant */
#define ETH_HEADER_LEN 14

/* Ethernet header */
struct Ethernet {
    uint8_t dst_mac_addr[6];
    uint8_t src_mac_addr[6];
    uint16_t eth_type;
};

/* IPv4 header */
struct IPv4 {
    uint8_t ver_hdrlen;
    uint8_t diff_services_field;
    uint16_t tot_len;
    uint16_t id;
    uint16_t flag_fragoffset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t chksum;
    uint32_t src_ip_addr;
    uint32_t dst_ip_addr;
};

/* TCP header */
struct TCP {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t hdrlen_flags;
    uint16_t win_size;
    uint16_t chksum;
    uint16_t urgent_ptr;
};

/* function prototypes - defined in cpp */
uint8_t get_ip_version(const IPv4 *ip);
uint8_t get_ip_hdrlen(const IPv4 *ip);
uint8_t get_tcp_hdrlen(const TCP *tcp);
void print_src_mac_addr(const Ethernet *eth);
void print_dst_mac_addr(const Ethernet *eth);
void print_src_ip_addr(const IPv4 *ip);
void print_dst_ip_addr(const IPv4 *ip);

