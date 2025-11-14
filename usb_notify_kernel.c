#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

#define NETLINK_USB 31

static struct sock *nl_sk = NULL;

/* ========= USB EVENT HANDLER ========= */
static int usb_notify(struct notifier_block *self, unsigned long action, void *data)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char msg[128];
    int msg_size;

    struct usb_device *udev = data;

    switch (action) {
        case USB_DEVICE_ADD:
            snprintf(msg, sizeof(msg), "USB Device Added: VID=%04x PID=%04x",
                     udev->descriptor.idVendor, udev->descriptor.idProduct);
            break;

        case USB_DEVICE_REMOVE:
            snprintf(msg, sizeof(msg), "USB Device Removed");
            break;

        default:
            return NOTIFY_OK;
    }

    msg_size = strlen(msg) + 1;

    /* Netlink 메시지 생성 */
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "usb_notify_kernel: nlmsg_new failed\n");
        return NOTIFY_OK;
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    memcpy(nlmsg_data(nlh), msg, msg_size);

    /* User-space로 전송 */
    nlmsg_unicast(nl_sk, skb, 100);

    printk(KERN_INFO "usb_notify_kernel: sent msg -> %s\n", msg);

    return NOTIFY_OK;
}

/* USB notifier 구조체 */
static struct notifier_block usb_nb = {
    .notifier_call = usb_notify,
};

/* ========= INIT ========= */
static struct netlink_kernel_cfg cfg = {
    .input = NULL
};

static int __init usb_notify_init(void)
{
    printk(KERN_INFO "usb_notify_kernel loaded\n");

    cfg.input = NULL;

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USB, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "usb_notify_kernel: netlink_kernel_create failed\n");
        return -ENOMEM;
    }

    usb_register_notify(&usb_nb);
    return 0;
}

/* ========= EXIT ========= */
static void __exit usb_notify_exit(void)
{
    usb_unregister_notify(&usb_nb);

    if (nl_sk)
        netlink_kernel_release(nl_sk);

    printk(KERN_INFO "usb_notify_kernel unloaded\n");
}

MODULE_LICENSE("GPL");
module_init(usb_notify_init);
module_exit(usb_notify_exit);


