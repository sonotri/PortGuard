#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/types.h>
#include <linux/usb/ch9.h> // USB_CLASS_MASS_STORAGE 상수 포함
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>

#define NETLINK_USB 31
static struct sock *nl_sk = NULL;
#define USER_PID 100 // Netlink 메시지 수신 대상 PID


//1분 안에 5번 이상 등록/해제가 반복 감지되면 차단시키는 기능 구현부(NEW)
#define USB_IO_WINDOW_MS   (60*1000) //1분동안
#define USB_IO_THRESHOLD   5 //5번 이상

/* --- 1. 화이트리스트 정의부분 --- */
struct allowed_usb_device {
    __u16 idVendor;
    __u16 idProduct;
};

static const struct allowed_usb_device whitelist[] = {
    { 0x0781, 0x5591 }, 
    { 0x058f, 0x6387 }, 
    { 0x325d, 0x6310} //sonotri usb 등록
};

/* 화이트리스트와 1:1로 매핑되는 활동 테이블(NEW) */
struct usb_activity {
    __u16 idVendor;
    __u16 idProduct;
    unsigned long last_event_jiffies;  // 마지막 등록/해제 시각
    int event_count;                   // window 내 이벤트 횟수
    bool revoked;                      // true면 사실상 whitelist에서 제거된 상태
};

static struct usb_activity activity_table[ARRAY_SIZE(whitelist)];
static spinlock_t activity_lock;

/* --- 2. ID 테이블 (Mass Storage Claim) --- */
static const struct usb_device_id usb_drive_id_table[] = {
{
    .match_flags = USB_DEVICE_ID_MATCH_INT_CLASS,
    .bInterfaceClass = USB_CLASS_MASS_STORAGE,
},
{}
};
MODULE_DEVICE_TABLE(usb, usb_drive_id_table);

/* NEW: 내부적으로 activity_table에서 해당 (vid,pid) 엔트리를 찾는 함수 */
static struct usb_activity *find_activity(__u16 vid, __u16 pid)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(activity_table); i++) {
        if (activity_table[i].idVendor == vid &&
            activity_table[i].idProduct == pid) {
            return &activity_table[i];
        }
    }
    return NULL;
}

/* --- 3. 화이트리스트 검사 함수 --- */
static bool is_device_whitelisted(struct usb_device *dev)
{
    int i;
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);
    bool allowed = false;

    for (i = 0; i < ARRAY_SIZE(whitelist); i++) {
        if (whitelist[i].idVendor == vid && whitelist[i].idProduct == pid) {
            allowed = true;
            break;
        }
    }

    /* 화이트리스트에 있더라도 revoked 상태면 허용하지 않음(NEW) */
    if (allowed) {
        struct usb_activity *act;

        spin_lock(&activity_lock);
        act = find_activity(vid, pid);
        if (act && act->revoked) {
            allowed = false;
        }
        spin_unlock(&activity_lock);
    }

    return allowed;
}

/* --- 4. Netlink 메시지 전송 함수 --- */
static void netlink_send_msg(const char *message)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = strlen(message) + 1;
    int res;

    if (!nl_sk) return;

    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "PortGuard_kernel: nlmsg_new failed\n");
        return;
    }

    nlh = nlmsg_put(skb, 0, 0, NETLINK_USB, msg_size, 0); 
    if (!nlh) {
        kfree_skb(skb);
        printk(KERN_ERR "PortGuard_kernel: nlmsg_put failed\n");
        return;
    }
    memcpy(nlmsg_data(nlh), message, msg_size);

    res = nlmsg_unicast(nl_sk, skb, USER_PID);

    if (res < 0) {
        printk(KERN_ERR "PortGuard_kernel: nlmsg_unicast failed (%d) to PID %d\n", res, USER_PID);
    }
}

//I/O 활동 업데이트 & 빠른 반복 시 revoke 처리 함수(NEW)
// event_type: "PROBE" / "DISCONNECT" 등 로그용 문자열
static void update_activity_and_maybe_revoke(struct usb_device *dev, const char *event_type)
{
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);
    unsigned long now = jiffies;
    struct usb_activity *act;

    spin_lock(&activity_lock);

    act = find_activity(vid, pid);
    if (!act) {
        /* activity_table에 없는 VID/PID는 모니터링하지 않음 */
        spin_unlock(&activity_lock);
        return;
    }

    if (time_after(now,
                   act->last_event_jiffies +
                   msecs_to_jiffies(USB_IO_WINDOW_MS))) {
        /* 윈도우 벗어났으면 카운트 리셋 */
        act->event_count = 1;
    } else {
        act->event_count++;
    }

    act->last_event_jiffies = now;

    /* 아직 revoke 안 된 상태에서 threshold 초과하면 revoke */
    if (!act->revoked && act->event_count >= USB_IO_THRESHOLD) {
        char msg[256];

        act->revoked = true;

        snprintf(msg, sizeof(msg),
                 "[WARNING] Whitelisted USB VID=0x%04x, PID=0x%04x "
                 "detected rapid I/O (%d events/%dms). Revoking from whitelist.",
                 vid, pid,
                 act->event_count,
                 USB_IO_WINDOW_MS);

        /* 커널 로그 + 유저 공간 알림 */
        printk(KERN_WARNING "PortGuard Kernel Log Test: %s (event: %s)\n", msg, event_type);
        netlink_send_msg(msg);
    }

    spin_unlock(&activity_lock);
}

/* --- 5. PROBE 함수: 차단 및 알림 로직 --- */
static int usb_drive_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    struct usb_device *dev = interface_to_usbdev(interface);
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);
    char msg[128];
    int ret = 0; // 기본: 차단 (Claim)

    /* NEW: PROBE도 I/O 이벤트로 간주해서 활동 업데이트 */
    update_activity_and_maybe_revoke(dev, "PROBE");

    if (is_device_whitelisted(dev)) {
        // [허용]
        snprintf(msg, sizeof(msg), "[ALLOWED] Whitelisted USB Handed Off: VID=0x%04x, PID=0x%04x", vid, pid);
        netlink_send_msg(msg);
        ret = -ENODEV; // 실제 드라이버가 로드되도록 허용
    } else {
        // [차단]
        snprintf(msg, sizeof(msg), "[BLOCKED] Unauthorized USB Blocked: VID=0x%04x, PID=0x%04x", vid, pid);
        netlink_send_msg(msg);
        ret = 0; // 이 드라이버가 장치를 선점하여 차단
    }

    printk(KERN_INFO "PortGuard Kernel Log Test: %s\n", msg);
    return ret;
}

static void usb_drive_disconnect(struct usb_interface *interface)
{
    struct usb_device *dev = interface_to_usbdev(interface);
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);
    char msg[128];

    /* NEW: DISCONNECT도 I/O 이벤트로 카운트 */
    update_activity_and_maybe_revoke(dev, "DISCONNECT");

    // DISCONNECT 이벤트 알림
    snprintf(msg, sizeof(msg), "USB Device Disconnected: VID=0x%04x, PID=0x%04x", vid, pid);
    netlink_send_msg(msg);
    printk(KERN_INFO "PortGuard Kernel Log Test: %s\n", msg);
}

/* --- 6. USB Driver Structure --- */
static struct usb_driver usb_drive_driver = {
    .name = "PortGuard_kernel",
    .probe = usb_drive_probe,
    .disconnect = usb_drive_disconnect,
    .id_table = usb_drive_id_table,
};

/* --- 7. INIT & EXIT (Netlink 통합) --- */
static struct netlink_kernel_cfg cfg = {
    .input = NULL
};

static int __init hello_init(void)
{
    int result;
    int i;

    printk(KERN_INFO "PortGuard Kernel Log Test: USB Security Filter Driver Registered.\n");

    /* NEW: activity 테이블 초기화 */
    spin_lock_init(&activity_lock);
    for (i = 0; i < ARRAY_SIZE(whitelist); i++) {
        activity_table[i].idVendor  = whitelist[i].idVendor;
        activity_table[i].idProduct = whitelist[i].idProduct;
        activity_table[i].last_event_jiffies = 0;
        activity_table[i].event_count = 0;
        activity_table[i].revoked = false;
    }

    // Netlink 소켓 생성
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USB, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "PortGuard Kernel Log Test: Netlink socket creation failed!\n");
        return -ENOMEM;
    }

    // USB 드라이버 등록
    result = usb_register(&usb_drive_driver);
    if (result) {
        printk(KERN_ERR "PortGuard Kernel Log Test: Failed to register USB security driver: %d\n", result);
        netlink_kernel_release(nl_sk);
        return result;
    }
    return 0;
}

static void __exit hello_exit(void)
{
    usb_deregister(&usb_drive_driver);
    if (nl_sk)
        netlink_kernel_release(nl_sk);

    printk(KERN_INFO "PortGuard Kernel Log Test: USB Security Filter Driver Unregistered.\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kamatte, Moon1, Sonotri");
MODULE_DESCRIPTION("Active USB Whitelist/Blocker Module with Netlink Notification and I/O Activity Monitoring");
