#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h> 

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

    // 2. 바인딩 주소 설정
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = USER_PID;

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
            
            if (nlh->nlmsg_type == NETLINK_USB || nlh->nlmsg_type == NLMSG_DONE) { 
                char *msg_data = (char *)NLMSG_DATA(nlh);

                printf("Received from kernel: %s\n", msg_data);

                // --- GUI 알림 로직: 굵은 글씨 강조만 적용 ---
                char cmd[512];
                char html_formatted_msg[512]; 
                char *title;
                char *urgency_flag;
                char *icon_flag;
                
                // 메시지 내용에 따라 제목, 중요도, 아이콘 설정
                if (strstr(msg_data, "[BLOCKED]")) {
                    title = "USB SECURITY ALERT! (BLOCKED)";
                    urgency_flag = "-u critical"; 
                    icon_flag = "-i dialog-warning";
                    
                    // 굵게만 처리
                    snprintf(html_formatted_msg, sizeof(html_formatted_msg), 
                             "<b>%s</b>", msg_data);

                } else if (strstr(msg_data, "[ALLOWED]")) {
                    title = "USB Device Allowed";
                    urgency_flag = "-u normal";
                    icon_flag = "-i dialog-information";

                    // 굵게만 처리
                    snprintf(html_formatted_msg, sizeof(html_formatted_msg), 
                             "<b>%s</b>", msg_data);
                    
                } else {
                    title = "USB Device Disconnected";
                    urgency_flag = "-u low";
                    icon_flag = "";
                    
                    // 일반 메시지는 굵게만 처리
                    snprintf(html_formatted_msg, sizeof(html_formatted_msg), "<b>%s</b>", msg_data);
                }
                
                // notify-send 명령 생성: TYPE:NAME:VALUE 형태를 사용 (최종 안정화)
                if (snprintf(cmd, sizeof(cmd), "notify-send %s %s -h string:markup:true '%s' '%s'", 
                             urgency_flag, icon_flag, title, html_formatted_msg) < sizeof(cmd)) {
                    system(cmd);
                }
            }
        } else if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("ERROR: recvmsg failed");
            break;
        }
    }

    close(sock_fd);
    return 0;
}
