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
#include "ucs_netlink.h"
#include "status.h"


ucs_status_t netlink_socket_create(struct netlink_socket *nl_sock)
{
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        return UCS_ERR_IO_ERROR;
    }

    memset(nl_sock, 0, sizeof(*nl_sock));
    nl_sock->fd = fd;
    nl_sock->local.nl_family = AF_NETLINK;

    if (bind(fd, (struct sockaddr *)&nl_sock->local, sizeof(nl_sock->local)) < 0) {
        close(fd);
        return UCS_ERR_IO_ERROR;
    }

    return UCS_OK;
}

void netlink_socket_close(struct netlink_socket *nl_sock)
{
    if (nl_sock->fd >= 0) {
        close(nl_sock->fd);
        nl_sock->fd = -1;
    }
}

void netlink_msg_init(struct netlink_message *msg, int type, int flags, int nlmsg_len)
{
    struct nlmsghdr *nlh;

    memset(msg, 0, sizeof(*msg));
    nlh = (struct nlmsghdr *)msg->buf;
    nlh->nlmsg_len = NLMSG_LENGTH(nlmsg_len);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();
}

ucs_status_t netlink_send(struct netlink_socket *nl_sock, struct netlink_message *msg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)msg->buf;

    /* send the request */
    if (send(nl_sock->fd, nlh, nlh->nlmsg_len, 0) < 0) {
        printf("failed to send netlink message\n");
        close(nl_sock->fd);
        return UCS_ERR_IO_ERROR;
    }

    return UCS_OK;
}

int netlink_recv(struct netlink_socket *nl_sock, struct netlink_message *msg)
{
    int ret;

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

ucs_nl_parse_status_t netlink_parse_msg(struct netlink_message *msg,
                                        int msg_len,
                                        void (*parse_cb)(struct nlmsghdr *h, void *arg),
                                        void *arg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)msg->buf;

    for (nlh; NLMSG_OK(nlh, msg_len); nlh = NLMSG_NEXT(nlh, msg_len)) {
        if (nlh->nlmsg_type == NLMSG_DONE) {
            return UCS_NL_STATUS_DONE;
        }

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
            return UCS_NL_STATUS_ERROR;
        }

        parse_cb(nlh, arg);
    }

    return UCS_NL_STATUS_OK;
}

int netlink_parse_rtattr(struct rtattr *attrs[], int max,
                         struct rtattr *rta, int len)
{
    memset(attrs, 0, sizeof(struct rtattr *) * (max + 1));

    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type <= max) {
            attrs[rta->rta_type] = rta;
        }
    }

    return 0;
}

static void create_ipv6_mask(struct in6_addr *mask, int prefix_len)
{
    int i;
    for (i = 0; i < 16; i++) {
        if (prefix_len >= 8) {
            mask->s6_addr[i] = 0xFF;
            prefix_len -= 8;
        } else if (prefix_len > 0) {
            mask->s6_addr[i] = (0xFF00 >> prefix_len) & 0xFF;
            prefix_len = 0;
        } else {
            mask->s6_addr[i] = 0;
        }
    }
}

static void parse_route_cb(struct nlmsghdr *nlh, void *arg)
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
    if (*oif == info->if_index) {
        if (info->family == AF_INET) {
            struct in_addr *addr = RTA_DATA(rta[RTA_DST]);
            uint32_t mask = htonl(~((1 << (32 - rtm->rtm_dst_len)) - 1));
            if ((info->remote_addr.ipv4.s_addr & mask) == (addr->s_addr & mask)) {
                    info->reachable = 1;
            }
        } else { /* AF_INET6 */
            int i;
            struct in6_addr *network_addr = RTA_DATA(rta[RTA_DST]);
            struct in6_addr *dest = (struct in6_addr *)&info->remote_addr.ipv6;
            struct in6_addr mask, masked_dest, masked_network;
            create_ipv6_mask(&mask, rtm->rtm_dst_len);

            for (i = 0; i < 16; i++) {
                masked_dest.s6_addr[i] = dest->s6_addr[i] & mask.s6_addr[i];
                masked_network.s6_addr[i] = network_addr->s6_addr[i] & mask.s6_addr[i];
            }

            if (memcmp(&masked_dest, &masked_network, sizeof(struct in6_addr)) == 0) {
                info->reachable = 1;
            }
        }
    }

    info->prefix_len = rtm->rtm_dst_len;
}

int netlink_route_is_reachable(const char *iface, struct sockaddr_storage *sa_remote)
{
    int ret, len;
    struct netlink_socket nl_sock;
    struct netlink_message msg, recv_msg;
    struct rtmsg *rtm;
    ucs_nl_parse_status_t parse_status;
    struct route_info info = {0};

    info.if_index = if_nametoindex(iface);
    if (info.if_index == 0) {
        return 0; /* interface not found */
    }

    info.family = sa_remote->ss_family;
    if (info.family == AF_INET) {
        info.remote_addr.ipv4 = ((struct sockaddr_in *)sa_remote)->sin_addr;
    } else if (info.family == AF_INET6) {
        info.remote_addr.ipv6 = ((struct sockaddr_in6 *)sa_remote)->sin6_addr;
    } else {
        return 0; /* unsupported address family */
    }

    ret = netlink_socket_create(&nl_sock);
    if (ret != UCS_OK) {
        return 0;
    }

    netlink_msg_init(&msg, RTM_GETROUTE,
                     NLM_F_REQUEST | NLM_F_DUMP,
                     sizeof(struct rtmsg));

    rtm = (struct rtmsg *)NLMSG_DATA(&msg.buf);
    rtm->rtm_family = info.family;
    rtm->rtm_table = RT_TABLE_MAIN;

    ret = netlink_send(&nl_sock, &msg);
    if (ret < 0) {
        goto out;
    }

    while ((len = netlink_recv(&nl_sock, &recv_msg)) > 0) {
        parse_status = netlink_parse_msg(&recv_msg, len, parse_route_cb, &info);
        if (parse_status == UCS_NL_STATUS_DONE ||
            parse_status == UCS_NL_STATUS_ERROR ||
            info.reachable) {
            break;
        }
    }

    if (len < 0) {
        printf("netlink_recv returned %d (%s)\n", len, strerror(len));
    }

out:
    netlink_socket_close(&nl_sock);
    return info.reachable;
}