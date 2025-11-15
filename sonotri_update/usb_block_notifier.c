#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h> // for errno

#define NETLINK_USB 31
#define USER_PID 100

int main()
{
    int sock_fd;
    struct sockaddr_nl src_addr;
    
    // 1. Netlink 소켓 생성
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USB);
    if (sock_fd < 0) {
        perror("ERROR: Failed to create socket");
        return -1;
    }

    // 2. 바인딩 주소 설정 (커널 모듈의 타겟 PID 100과 일치해야 함)
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = USER_PID;    // user-space process pid

    // 3. 소켓 바인딩
    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("ERROR: Failed to bind socket");
        close(sock_fd);
        return -1;
    }

    printf("USB Event Notifier running. Listening for Netlink messages on PID %d...\n", USER_PID);

    // 4. 메시지 수신 루프
    while (1) {
        char buffer[1024];
        struct iovec iov = { buffer, sizeof(buffer) };
        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
        };
        
        int ret = recvmsg(sock_fd, &msg, 0);

        if (ret > 0) {
            struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
            
            // Netlink 메시지 유형 확인
            if (nlh->nlmsg_type == NETLINK_USB || nlh->nlmsg_type == NLMSG_DONE) {
                char *msg_data = (char *)NLMSG_DATA(nlh);

                printf("Received from kernel: %s\n", msg_data);

                // ---- notify-send GUI 알림 ----
                char cmd[512];
                char *title;
                
                // 메시지 내용에 따라 제목 변경
                if (strstr(msg_data, "[BLOCKED]")) {
                    title = "USB Security Alert (BLOCKED)";
                } else if (strstr(msg_data, "[ALLOWED]")) {
                    title = "USB Event Notification (ALLOWED)";
                } else {
                    title = "USB Event Notification";
                }
                
                // snprintf로 명령 생성
                if (snprintf(cmd, sizeof(cmd), "notify-send '%s' '%s'", title, msg_data) < sizeof(cmd)) {
                    system(cmd);
                }
            }
        } else if (ret < 0) {
            if (errno == EINTR) {
                continue; // Signal received, retry recvmsg
            }
            perror("ERROR: recvmsg failed");
            break;
        }
    }

    close(sock_fd);
    return 0;
}
