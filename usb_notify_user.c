#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_USB 31

int main()
{
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USB);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = 100;   // user-space process pid

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind");
        return -1;
    }

    while (1) {
        char buffer[1024];
        int ret = recv(sock_fd, buffer, sizeof(buffer), 0);

        if (ret > 0) {
            char *msg = buffer + NLMSG_HDRLEN;

            printf("Received from kernel: %s\n", msg);

            // ---- notify-send GUI 알림 ----
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                     "notify-send 'USB Event' '%s'", msg);
            system(cmd);
        }
    }

    close(sock_fd);
    return 0;
}


