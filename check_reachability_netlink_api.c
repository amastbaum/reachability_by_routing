#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ucs_netlink.h"

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <destination_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *interface = argv[1];
    const char *dest_ip = argv[2];
    
    struct sockaddr_storage sa_remote;
    struct sockaddr_in *sa_remote_in = (struct sockaddr_in*)&sa_remote;
    
    // Convert the destination IP string to sockaddr_in for sa_remote (IPv4)
    sa_remote_in->sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[2], &sa_remote_in->sin_addr) != 1) {
        perror("inet_pton");
        return EXIT_FAILURE;
    }

    int result = netlink_route_is_reachable(interface, &sa_remote);

    if (result == 1) {
        printf("IP %s is reachable through %s\n", dest_ip, interface);
    } else if (result == 0) {
        printf("IP %s is NOT reachable through %s\n", dest_ip, interface);
    } else {
        printf("An error occurred while checking reachability\n");
    }

    return 0;
}