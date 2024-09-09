#include "ucs_netlink.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>


struct route_info {
    int if_index;
    int family;

    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } dest;

    int prefix_len;
    int reachable;
};


static int netlink_socket_create(struct netlink_socket *nl_sock)
{
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        return -errno;
    }

    memset(nl_sock, 0, sizeof(*nl_sock));
    nl_sock->fd = fd;

    nl_sock->local.nl_family = AF_NETLINK;
    // nl_sock->local.nl_pid = getpid();

    if (bind(fd, (struct sockaddr *)&nl_sock->local, sizeof(nl_sock->local)) < 0) {
        close(fd);
        return -errno;
    }

    return 0;
}

static void netlink_socket_close(struct netlink_socket *nl_sock)
{
    if (nl_sock->fd >= 0) {
        close(nl_sock->fd);
        nl_sock->fd = -1;
    }
}

void netlink_msg_init(struct netlink_message *msg, int type, int flags)
{
    memset(msg, 0, sizeof(*msg));
    msg->hdr.nlmsg_len = NLMSG_LENGTH(0);
    msg->hdr.nlmsg_type = type;
    msg->hdr.nlmsg_flags = flags;
    msg->hdr.nlmsg_seq = 0;
    msg->hdr.nlmsg_pid = getpid();
}

static int netlink_send(struct netlink_socket *nl_sock, struct netlink_message *msg)
{
    struct iovec iov = {
        .iov_base = &msg->hdr,
        .iov_len = msg->hdr.nlmsg_len
    };

    struct msghdr msghdr = {
        .msg_name = &nl_sock->peer,
        .msg_namelen = sizeof(nl_sock->peer),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    ssize_t ret = sendmsg(nl_sock->fd, &msghdr, 0);
    if (ret < 0) {
        return -errno;
    }

    return 0;
}

static int netlink_recv(struct netlink_socket *nl_sock, struct netlink_message *msg)
{
    struct iovec iov = {
        .iov_base = msg->buf,
        .iov_len = sizeof(msg->buf)
    };
    struct msghdr msghdr = {
        .msg_name = &nl_sock->peer,
        .msg_namelen = sizeof(nl_sock->peer),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    ssize_t ret = recvmsg(nl_sock->fd, &msghdr, 0);
    if (ret < 0) {
        return -errno;
    }

    if (ret == 0) {
        return -ENODATA;
    }

    msg->hdr = *(struct nlmsghdr *)msg->buf;
    return ret;
}

static int netlink_parse_msg(struct netlink_message *msg, void (*callback)(struct nlmsghdr *h, void *arg), void *arg)
{
    struct nlmsghdr *nlh;
    int len = msg->hdr.nlmsg_len;
    int remain = len - sizeof(struct nlmsghdr);

    for (nlh = &msg->hdr; NLMSG_OK(nlh, remain); nlh = NLMSG_NEXT(nlh, remain)) {
        if (nlh->nlmsg_type == NLMSG_DONE) {
            return 0;
        }

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
            return -err->error;
        }

        callback(nlh, arg);
    }

    return 0;
}

static int netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta, len);
    }

    return 0;
}

static void parse_route(struct nlmsghdr *nlh, void *arg)
{
    struct route_info *info = (struct route_info *)arg;
    struct rtmsg *rtm = NLMSG_DATA(nlh);
    struct rtattr *rta[RTA_MAX + 1];

    printf("#1\n");
    if (rtm->rtm_family != info->family) {
        return;
    }

    netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(nlh));

    if (rta[RTA_DST]) {
        if (info->family == AF_INET) {
            struct in_addr *addr = RTA_DATA(rta[RTA_DST]);
            if (memcmp(&info->dest.ipv4, addr, sizeof(struct in_addr)) == 0) {
                info->reachable = 1;
            }
        } else { // AF_INET6
            struct in6_addr *addr = RTA_DATA(rta[RTA_DST]);
            if (memcmp(&info->dest.ipv6, addr, sizeof(struct in6_addr)) == 0) {
                info->reachable = 1;
            }
        }
    }

    if (rta[RTA_OIF]) {
        int *oif = RTA_DATA(rta[RTA_OIF]);
        printf("oif: %d\n", *oif);
        printf("info->if_index: %d\n", info->if_index);
        if (*oif == info->if_index) {
            info->reachable = 1;
        }
    }

    info->prefix_len = rtm->rtm_dst_len;
}

int netlink_route_is_reachable(const char *iface, struct sockaddr_storage *dest)
{
    struct netlink_socket nl_sock;
    struct netlink_message msg;
    struct route_info info = {0};
    int ret;

    info.if_index = if_nametoindex(iface);
    if (info.if_index == 0) {
        return -1; /* interface not found */
    }

    info.family = dest->ss_family;
    if (info.family == AF_INET) {
        info.dest.ipv4 = ((struct sockaddr_in *)dest)->sin_addr;
    } else if (info.family == AF_INET6) {
        info.dest.ipv6 = ((struct sockaddr_in6 *)dest)->sin6_addr;
    } else {
        return -1; /* unsupported address family */
    }

    ret = netlink_socket_create(&nl_sock);
    if (ret < 0) {
        return -1;
    }

    netlink_msg_init(&msg, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP);

    struct rtmsg *rtm = NLMSG_DATA(&msg.hdr);
    rtm->rtm_family = info.family;
    rtm->rtm_table = RT_TABLE_MAIN;

    ret = netlink_send(&nl_sock, &msg);
    if (ret < 0) {
        netlink_socket_close(&nl_sock);
        return -1;
    }

    while ((ret = netlink_recv(&nl_sock, &msg)) > 0) {
        ret = netlink_parse_msg(&msg, parse_route, &info);
        if (ret < 0 || info.reachable) {
            break;
        }
    }

    netlink_socket_close(&nl_sock);

    return info.reachable;
}