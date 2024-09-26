#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ucs_netlink.h"


int get_routing_table_size(int af_family)
{
    int ret, len, total_len;
    struct netlink_socket nl_sock;
    struct netlink_message msg, recv_msg;
    struct rtmsg *rtm;

    ret = netlink_socket_create(&nl_sock);
    if (ret != UCS_OK) {
        return 0;
    }

    netlink_msg_init(&msg, RTM_GETROUTE,
                     NLM_F_REQUEST | NLM_F_DUMP,
                     sizeof(struct rtmsg));

    rtm = (struct rtmsg *)NLMSG_DATA(&msg.buf);
    rtm->rtm_family = af_family;
    rtm->rtm_table = RT_TABLE_MAIN;

    ret = netlink_send(&nl_sock, &msg);
    if (ret < 0) {
        goto out;
    }

    len = netlink_recv(&nl_sock, &recv_msg);

out:
    netlink_socket_close(&nl_sock);
    return len;
}

int main(int argc, char *argv[])
{
    int result_4 = get_routing_table_size(AF_INET);
    int result_6 = get_routing_table_size(AF_INET6);
    printf("%d\n", result_6 > result_4 ? result_6 : result_4);

    return 0;
}