#ifndef NETLINK_WRAPPER_H
#define NETLINK_WRAPPER_H

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "status.h"

#define NETLINK_BUFFER_SIZE 8192

typedef enum ucs_nl_parse_status {
    UCS_NL_STATUS_OK = 0,
    UCS_NL_STATUS_DONE = 1,
    UCS_NL_STATUS_ERROR = 2,
} ucs_nl_parse_status_t;

struct netlink_socket {
    int fd;
    struct sockaddr_nl local;
    struct sockaddr_nl peer;
};

struct route_info {
    int if_index;
    int family;

    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } remote_addr;

    int prefix_len;
    int reachable;
};

struct netlink_message {
    char buf[NETLINK_BUFFER_SIZE];
};

// Socket Management
ucs_status_t netlink_socket_create(struct netlink_socket *nl_sock);
void netlink_socket_close(struct netlink_socket *nl_sock);

// Message Construction
void netlink_msg_init(struct netlink_message *msg, int type,
                      int flags, int nlmsg_len);

// Message Sending and Receiving
ucs_status_t netlink_send(struct netlink_socket *nl_sock, struct netlink_message *msg);
int netlink_recv(struct netlink_socket *nl_sock, struct netlink_message *msg);

// Message Parsing
ucs_nl_parse_status_t netlink_parse_msg(struct netlink_message *msg,
                                        int msg_len,
                                        void (*callback)(struct nlmsghdr *h, void *arg),
                                        void *arg);
int netlink_parse_rtattr(struct rtattr *attrs[], int max, struct rtattr *rta, int len);

// Routing-specific Functions
int netlink_get_routes(struct netlink_socket *nl_sock, int family);
int netlink_route_is_reachable(const char *iface, struct sockaddr_storage *dest);

#endif // NETLINK_WRAPPER_H