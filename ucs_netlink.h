#ifndef NETLINK_WRAPPER_H
#define NETLINK_WRAPPER_H

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define NETLINK_BUFFER_SIZE 8192

struct netlink_socket {
    int fd;
    struct sockaddr_nl local;
    struct sockaddr_nl peer;
};

struct netlink_message {
    struct nlmsghdr hdr;
    char buf[NETLINK_BUFFER_SIZE];
};

// Routing-specific Functions
int netlink_get_routes(struct netlink_socket *nl_sock, int family);
int netlink_route_is_reachable(const char *iface, struct sockaddr_storage *dest);

#endif // NETLINK_WRAPPER_H