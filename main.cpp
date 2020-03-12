#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include "packet_structure.h"

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;                                     //header
        const u_char* packet;                                           //packet
        int res = pcap_next_ex(handle, &header, &packet);               //read packet
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        //
        printf("------packet capture------ \n");

        Ethernet * eth_header = (Ethernet*)(packet);

        printf("dmac = %02X:%02X:%02X:%02X:%02X:%02X\n", eth_header->dmac[0], eth_header->dmac[1],
                eth_header->dmac[2], eth_header->dmac[3],
                eth_header->dmac[4], eth_header->dmac[5]);

        printf("smac = %02X:%02X:%02X:%02X:%02X:%02X\n", eth_header->smac[0], eth_header->smac[1],
                eth_header->smac[2], eth_header->smac[3],
                eth_header->smac[4], eth_header->smac[5]);


        //ip sip, dip

        IP *ip_header;
        packet += sizeof(eth_header);
        ip_header= (IP*)(packet);

        printf("sip = %d.%d.%d.%d\n", ip_header->sip[0], ip_header->sip[1], ip_header->sip[2], ip_header->sip[3]);
        printf("dip = %d.%d.%d.%d\n", ip_header->dip[0], ip_header->dip[1], ip_header->dip[2], ip_header->dip[3]);

        //tcp sport, dport

        TCP * tcp_header;
        packet += sizeof(ip_header);
        tcp_header= (TCP*)(packet);

        printf("sport = %d\n", tcp_header->sport);
        printf("dport = %d\n", tcp_header->dport);



        //
        //    printf("%u bytes captured\n", header->caplen);
        printf("%u byte captured\n\n", header->caplen);
    }


    pcap_close(handle);
    return 0;
}

