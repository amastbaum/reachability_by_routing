#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ucs_netlink.h"

int main(int argc, char *argv[])
{
    const char *interface;
    const char *dest_ip;
    sa_family_t sa_family;
    struct sockaddr_in sa_remote_in;
    struct sockaddr_in6 sa_remote_in6;
    struct sockaddr_storage *sa_remote;
    void *sin_addr;

    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <destination_ip> [-6]\n", argv[0]);
        return EXIT_FAILURE;
    }

    interface = argv[1];
    dest_ip = argv[2];
    
    if (argc == 3) {
        sa_remote_in.sin_family = AF_INET;
        sa_remote = (struct sockaddr_storage *)&sa_remote_in;
        sin_addr = &sa_remote_in.sin_addr;
    } else if (argc == 4) {
        sa_remote_in6.sin6_family = AF_INET6;
        sa_remote = (struct sockaddr_storage *)&sa_remote_in6;
        sin_addr = &sa_remote_in6.sin6_addr;
    }

    // Convert the destination IP string to sockaddr_in/sockaddr_in6 for sa_remote
    if (inet_pton(sa_remote->ss_family, dest_ip, sin_addr) != 1) {
        perror("inet_pton");
        return EXIT_FAILURE;
    }

    int result = netlink_route_is_reachable(interface, sa_remote);

    if (result == 1) {
        printf("IP %s is reachable through %s\n", dest_ip, interface);
    } else if (result == 0) {
        printf("IP %s is NOT reachable through %s\n", dest_ip, interface);
    } else {
        printf("An error occurred while checking reachability\n");
    }

    return 0;
}