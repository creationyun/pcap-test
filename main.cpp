#include <pcap.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include "protocol.h"

void usage() {
    /* print usage */
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    /* check argument number */
    if (argc != 2) {
        usage();
        return -1;
    }

    /** variables
     * dev: network interface
     * errbuf: error message used in opening pcap
     * handle: pcap handler
     */
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    /* check nullptr error */
    if (handle == nullptr) {
        fprintf(stderr, "Error: pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    /* capturing on loop */
    while (true) {
        /** variables
         * header: packet header
         * packet: packet content
         * res: result code of pcap reading
         */
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;         // not captured
        if (res == -1 || res == -2) {   // quit
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        // printf(" ** %u bytes captured ** \n", header->caplen);

        /* adjust the packet with Ethernet protocol */
        Ethernet *ethernet = (Ethernet*) packet;

        /* check if EtherType is IPv4 or not */
        if (ntohs(ethernet->eth_type) != 0x0800) {
            // printf("Info: this packet is not IPv4 (EtherType == 0x%x)\n\n", ethernet->eth_type);
            continue;
        }

        /* adjust the packet with IPv4 protocol */
        IPv4 *ipv4 = (IPv4*) (packet + ETH_HEADER_LEN);

        /* check if IP protocol type is TCP or not */
        if (ipv4->proto != 0x06) {
            // printf("Info: this packet is not TCP (IPv4_Protocol == 0x%x)\n\n", ipv4->proto);
            continue;
        }

        /* get IP header length */
        uint8_t ip_hdrlen = get_ip_hdrlen(ipv4);

        /* adjust the packet with TCP protocol */
        TCP *tcp = (TCP*) (packet + ETH_HEADER_LEN + ip_hdrlen);

        /* get TCP header length */
        uint8_t tcp_hdrlen = get_tcp_hdrlen(tcp);

        /* adjust the packet to data (payload) */
        const uint8_t *data = packet + ETH_HEADER_LEN + ip_hdrlen + tcp_hdrlen;

        /* print packet information */
        printf(" ** TCP/IP packet - %u bytes captured ** \n", header->caplen);
        printf("eth.src_mac = ");  print_src_mac_addr(ethernet);  printf("\n");
        printf("eth.dst_mac = ");  print_dst_mac_addr(ethernet);  printf("\n");
        printf("ipv4.src = ");  print_src_ip_addr(ipv4);  printf("\n");
        printf("ipv4.dst = ");  print_dst_ip_addr(ipv4);  printf("\n");
        printf("tcp.src_port = %d\n", ntohs(tcp->src_port));
        printf("tcp.dst_port = %d\n", ntohs(tcp->dst_port));
        printf("payload(data) = ");
        for (int i = 0; i < 16 && 
        (data + i) < (packet + ETH_HEADER_LEN + ntohs(ipv4->tot_len)); i++) {
            // ipv4->tot_len == ip_hdrlen + tcp_hdrlen + payload
            printf("%02x ", data[i]);
        }
        printf("\n\n");
    }

    /* close handler */
    pcap_close(handle);
}

