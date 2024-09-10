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
    } remote_addr;

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

static int netlink_send(struct netlink_socket *nl_sock, struct netlink_message *msg)
{
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;

    memset(msg->buf, 0, sizeof(msg->buf));
    nlh = (struct nlmsghdr *)msg->buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    rtm->rtm_family = AF_INET; /* ##### change to info->family */
    rtm->rtm_table = RT_TABLE_MAIN;

    /* send the request */
    if (send(nl_sock->fd, nlh, nlh->nlmsg_len, 0) < 0) {
        printf("failed to send netlink message\n");
        close(nl_sock->fd);
        return 0;
    }

    return 0;
}

static int netlink_recv(struct netlink_socket *nl_sock, struct netlink_message *msg)
{
    int ret;

    printf("msg: %p, msg->buf: %p, &msg->buf: %p, sizeof(msg->buf): %d\n", msg, msg->buf, &msg->buf, sizeof(msg->buf));
    memset(&msg->buf, 0, sizeof(msg->buf));
    ret = recv(nl_sock->fd, &msg->buf, sizeof(msg->buf), 0);
    if (ret < 0) {
        return -errno;
    }

    if (ret == 0) {
        return -ENODATA;
    }

    return ret;
}

static int netlink_parse_msg(struct netlink_message *msg,
                             int len,
                             enum ucs_netlink_parse_status *status,
                             void (*callback)(struct nlmsghdr *h, void *arg),
                             void *arg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)msg->buf;
    *status = UCS_NL_STATUS_OK;
    // int remain = len - sizeof(struct nlmsghdr);

    for (nlh; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
        printf("nlh->nlmsg_type #2: %d\n", nlh->nlmsg_type);
        if (nlh->nlmsg_type == NLMSG_DONE) {
            *status = UCS_NL_STATUS_DONE;
            printf("DONE\n");
            return 0;
        }

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
            *status = UCS_NL_STATUS_ERROR;
            printf("ERROR\n");
            return -err->error;
        }

        callback(nlh, arg);
    }

    return 0;
}

static int netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    printf("Parsing RTAs, len: %d\n", len);
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        printf("rta->rta_type: %d, rta_len: %d\n", rta->rta_type, rta->rta_len);
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }
    }

    return 0;
}

static void parse_route(struct nlmsghdr *nlh, void *arg)
{
    struct route_info *info = (struct route_info *)arg;
    struct rtmsg *rtm = NLMSG_DATA(nlh);
    struct rtattr *rta[RTA_MAX + 1];

    rtm->rtm_family = info->family;
    rtm->rtm_table = RT_TABLE_MAIN;

    if (rtm->rtm_family != info->family) {
        return;
    }

    netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(nlh));

    if (rta[RTA_OIF] == NULL || rta[RTA_DST] == NULL) {
        return;
    }

    int *oif = RTA_DATA(rta[RTA_OIF]);
    printf("oif: %d\n", *oif);
    printf("info->if_index: %d\n", info->if_index);
    if (*oif == info->if_index) {
        printf("#3 - matching interfaces\n");
        if (info->family == AF_INET) {
            printf("#4 - IPv4\n");
            struct in_addr *addr = RTA_DATA(rta[RTA_DST]);
            uint32_t mask = htonl(~((1 << (32 - rtm->rtm_dst_len)) - 1));
            printf("#5 - addr: %u, remote: %u, mask: %u\n", addr->s_addr, info->remote_addr.ipv4.s_addr, mask);
            if ((info->remote_addr.ipv4.s_addr & mask) == (addr->s_addr & mask)) {
                    info->reachable = 1;
            }
        }
    }

    info->prefix_len = rtm->rtm_dst_len;
}

int netlink_route_is_reachable(const char *iface, struct sockaddr_storage *sa_remote)
{
    struct netlink_socket nl_sock;
    struct netlink_message msg, recv_msg;
    int ret, len;
    enum ucs_netlink_parse_status parse_status;
    struct route_info info = {0};

    info.if_index = if_nametoindex(iface);
    if (info.if_index == 0) {
        return -1; /* interface not found */
    }

    info.family = sa_remote->ss_family;
    if (info.family == AF_INET) {
        info.remote_addr.ipv4 = ((struct sockaddr_in *)sa_remote)->sin_addr;
    } else if (info.family == AF_INET6) {
        info.remote_addr.ipv6 = ((struct sockaddr_in6 *)sa_remote)->sin6_addr;
    } else {
        return -1; /* unsupported address family */
    }

    ret = netlink_socket_create(&nl_sock);
    if (ret < 0) {
        return -1;
    }

    ret = netlink_send(&nl_sock, &msg);
    if (ret < 0) {
        netlink_socket_close(&nl_sock);
        return -1;
    }

    while ((len = netlink_recv(&nl_sock, &recv_msg)) > 0) {
        printf("buf->nlmsg_len: %d\n", ((struct nlmsghdr *)recv_msg.buf)->nlmsg_len);
        // ((struct nlmsghdr *)recv_msg.buf)->nlmsg_len = len;
        printf("len = recv(): %d\n", len);
        ret = netlink_parse_msg(&recv_msg, len, &parse_status, parse_route, &info);
        if (parse_status == UCS_NL_STATUS_DONE ||
            parse_status == UCS_NL_STATUS_ERROR || /* redundant - should handle
                                                      'status' and 'ret' later */
            ret < 0 || info.reachable) {
            break;
        }
    }

    netlink_socket_close(&nl_sock);

    return info.reachable;
}