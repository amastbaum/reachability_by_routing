#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 8192

// Helper function to add attributes to the Netlink message
int add_attribute(struct nlmsghdr *nlh, int maxlen, int type, void *data, int len) {
    struct rtattr *rta;
    int rtalen = RTA_LENGTH(len);

    if (NLMSG_ALIGN(nlh->nlmsg_len) + rtalen > maxlen)
        return -1;

    rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = rtalen;
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + rtalen;

    return 0;
}

int get_route_for_destination(const char *interface_name, const char *dest_ip) {
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } request;

    // Create Netlink socket
    int sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    // Zero out the request structure and set necessary values
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.nlh.nlmsg_type = RTM_GETROUTE;
    request.nlh.nlmsg_flags = NLM_F_REQUEST;
    request.rtm.rtm_family = AF_INET;  // IPv4
    request.rtm.rtm_dst_len = 32;      // Full 32-bit IP address for destination

    // Get the interface index by name
    unsigned int if_index = if_nametoindex(interface_name);
    if (if_index == 0) {
        perror("if_nametoindex");
        close(sock_fd);
        return -1;
    }

    // Specify the destination address as a filter
    struct in_addr dest_addr;
    if (inet_pton(AF_INET, dest_ip, &dest_addr) != 1) {
        perror("inet_pton");
        close(sock_fd);
        return -1;
    }

    // Add the destination address attribute to the Netlink message
    add_attribute(&request.nlh, sizeof(request), RTA_DST, &dest_addr, sizeof(dest_addr));

    // Send the Netlink message
    if (send(sock_fd, &request, request.nlh.nlmsg_len, 0) < 0) {
        perror("send");
        close(sock_fd);
        return -1;
    }

    // Buffer for responses
    char buffer[BUFFER_SIZE];
    ssize_t len;

    // Receive the routing information
    len = recv(sock_fd, buffer, sizeof(buffer), 0);
    printf("messgae length: %d\n", len);
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

    // Loop through all received messages
    for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE) {
            break;  // End of messages
        }

        if (nlh->nlmsg_type == RTM_NEWROUTE) {
            struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
            struct rtattr *rta = (struct rtattr *)RTM_RTA(rtm);
            int rta_len = RTM_PAYLOAD(nlh);
            printf("    rta_len: %d\n", rta_len);

            // Parse the routing entry and check attributes
            while (RTA_OK(rta, rta_len)) {
                if (rta->rta_type == RTA_DST) {
                    struct in_addr *addr = RTA_DATA(rta);
                    char ip_str[32] = {0};
                    inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, ip_str, sizeof(ip_str))
                }
                if (rta->rta_type == RTA_OIF) {
                    int route_if_index = *(int *)RTA_DATA(rta);
                    printf("    RTA_OIF: %d\n", route_if_index);
                    if (route_if_index == if_index) {
                        printf("Route to %s found via interface %s (index: %d)\n", dest_ip, interface_name, if_index);
                        close(sock_fd);
                        return 0;
                    }
                }
                rta = RTA_NEXT(rta, rta_len);
            }
        }
    }

    printf("No route to %s via interface %s\n", dest_ip, interface_name);
    close(sock_fd);
    return -1;
}

int main(int argc, char *argv[])
{
    const char *interface;
    const char *dest_ip;
    // sa_family_t sa_family;
    // struct sockaddr_in sa_remote_in;
    // struct sockaddr_in6 sa_remote_in6;
    // struct sockaddr_storage *sa_remote;
    // void *sin_addr;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <destination_ip>\n", argv[0]);
        return -1;
    }

    interface = argv[1];
    dest_ip = argv[2];

    // sa_remote_in.sin_family = AF_INET;
    // sa_remote = (struct sockaddr_storage *)&sa_remote_in;
    // sin_addr = &sa_remote_in.sin_addr;

    // // Convert the destination IP string to sockaddr_in/sockaddr_in6 for sa_remote
    // if (inet_pton(sa_remote->ss_family, dest_ip, sin_addr) != 1) {
    //     perror("inet_pton");
    //     return -1;
    // }

    // const char *interface = "enp131s0f0np0";     // Replace with your interface name
    // const char *dest_ip = "1.1.1.0";    // Replace with the destination IP you want to check

    get_route_for_destination(interface, dest_ip);
    return 0;
}