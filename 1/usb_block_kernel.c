#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/types.h>
#include <linux/usb/ch9.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

#define NETLINK_USB 31
static struct sock *nl_sk = NULL;
#define USER_PID 100 // Netlink 메시지 수신 대상 PID

/* --- 1. 화이트리스트 정의 --- */
struct allowed_usb_device {
    __u16 idVendor;
    __u16 idProduct;
};

static const struct allowed_usb_device whitelist[] = {
    { 0x0781, 0x5591 }, // SanDisk USB (예시용: 이 장치는 허용됨)
    // 여기에 허용할 장치를 추가하세요.
};

/* --- 2. ID 테이블 (Mass Storage Claim) --- */
static const struct usb_device_id usb_drive_id_table[] = {
{
    .match_flags = USB_DEVICE_ID_MATCH_INT_CLASS,
    .bInterfaceClass = USB_CLASS_MASS_STORAGE,
},
{}
};
MODULE_DEVICE_TABLE(usb, usb_drive_id_table);

/* --- 3. 화이트리스트 검사 함수 --- */
static bool is_device_whitelisted(struct usb_device *dev)
{
    int i;
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);

    for (i = 0; i < ARRAY_SIZE(whitelist); i++) {
        if (whitelist[i].idVendor == vid && whitelist[i].idProduct == pid) {
            return true;
        }
    }
    return false;
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

    nlh = nlmsg_put(skb, 0, 0, NETLINK_USB, msg_size, 0); // NETLINK_USB 대신 NLMSG_DONE 사용이 일반적이지만, 일관성을 위해 NETLINK_USB를 사용했습니다.
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


/* --- 5. PROBE 함수: 차단 및 알림 로직 --- */
static int usb_drive_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    struct usb_device *dev = interface_to_usbdev(interface);
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);
    char msg[128];
    int ret = 0; // 기본: 차단 (Claim)

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

    printk(KERN_INFO "kamatte@ubuntu: %s\n", msg);
    return ret;
}


static void usb_drive_disconnect(struct usb_interface *interface)
{
    struct usb_device *dev = interface_to_usbdev(interface);
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);
    char msg[128];

    // DISCONNECT는 ADD에서 차단/허용되었든 상관없이 발생
    snprintf(msg, sizeof(msg), "USB Device Disconnected: VID=0x%04x, PID=0x%04x", vid, pid);
    netlink_send_msg(msg);
    printk(KERN_INFO "kamatte@ubuntu: %s\n", msg);
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
    printk(KERN_INFO "kamatte@ubuntu: USB Security Filter Driver Registered.\n");

    // Netlink 소켓 생성
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USB, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "kamatte@ubuntu: Netlink socket creation failed!\n");
        return -ENOMEM;
    }

    // USB 드라이버 등록
    result = usb_register(&usb_drive_driver);
    if (result) {
        printk(KERN_ERR "kamatte@ubuntu: Failed to register USB security driver: %d\n", result);
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

    printk(KERN_INFO "kamatte@ubuntu: USB Security Filter Driver Unregistered.\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kamatte");
MODULE_DESCRIPTION("Active USB Whitelist/Blocker Module with Netlink Notification");
