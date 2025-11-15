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
#include <linux/jiffies.h>

#define NETLINK_USB 31
#define USER_PID 100

/* Netlink socket pointer */
static struct sock *nl_sk = NULL;

/* ------------------------------------------------------------------
 * 1. Whitelist definition
 * ------------------------------------------------------------------ */

struct allowed_usb_device {
    __u16 idVendor;
    __u16 idProduct;
};

static const struct allowed_usb_device whitelist[] = {
    { 0x0781, 0x5591 }, /* example: SanDisk USB */
    /* add more allowed devices here */
};

/* ------------------------------------------------------------------
 * 2. USB ID table (Mass Storage)
 * ------------------------------------------------------------------ */

static const struct usb_device_id usb_drive_id_table[] = {
    {
        .match_flags    = USB_DEVICE_ID_MATCH_INT_CLASS,
        .bInterfaceClass = USB_CLASS_MASS_STORAGE,
    },
    { }
};
MODULE_DEVICE_TABLE(usb, usb_drive_id_table);

/* ------------------------------------------------------------------
 * 3. Behavior-based detection (frequent connect/disconnect)
 * ------------------------------------------------------------------ */

#define USB_ACTIVITY_WINDOW    (10 * HZ)   /* 10 seconds */
#define USB_ACTIVITY_THRESHOLD 5           /* 5 events within window */
#define MAX_SUSPICIOUS_DEVICES 16

struct suspicious_usb {
    __u16 idVendor;
    __u16 idProduct;
    unsigned long first_jiffies;  /* window start time */
    unsigned int count;           /* number of events in window */
    bool blocked;                 /* treated as removed from whitelist */
};

static struct suspicious_usb suspicious_list[MAX_SUSPICIOUS_DEVICES];

/* forward declaration */
static void netlink_send_msg(const char *message);

/* ------------------------------------------------------------------
 * 4. Raw whitelist check (no behavior logic)
 * ------------------------------------------------------------------ */

static bool is_device_whitelisted_raw(__u16 vid, __u16 pid)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(whitelist); i++) {
        if (whitelist[i].idVendor == vid &&
            whitelist[i].idProduct == pid) {
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------
 * 5. Suspicious list helpers
 * ------------------------------------------------------------------ */

static struct suspicious_usb *find_suspicious(__u16 vid, __u16 pid)
{
    int i;

    for (i = 0; i < MAX_SUSPICIOUS_DEVICES; i++) {
        if (suspicious_list[i].idVendor == vid &&
            suspicious_list[i].idProduct == pid) {
            return &suspicious_list[i];
        }
    }
    return NULL;
}

static struct suspicious_usb *alloc_suspicious_slot(void)
{
    int i;

    for (i = 0; i < MAX_SUSPICIOUS_DEVICES; i++) {
        if (suspicious_list[i].idVendor == 0 &&
            suspicious_list[i].idProduct == 0) {
            return &suspicious_list[i];
        }
    }
    return NULL;
}

/* record connect/disconnect activity for a whitelist device */
static void record_usb_activity(__u16 vid, __u16 pid)
{
    struct suspicious_usb *entry;
    unsigned long now = jiffies;

    entry = find_suspicious(vid, pid);
    if (!entry) {
        entry = alloc_suspicious_slot();
        if (!entry)
            return; /* no space, give up */

        entry->idVendor      = vid;
        entry->idProduct     = pid;
        entry->first_jiffies = now;
        entry->count         = 1;
        entry->blocked       = false;
        return;
    }

    /* if time window expired, reset counter and window */
    if (time_after(now, entry->first_jiffies + USB_ACTIVITY_WINDOW)) {
        entry->first_jiffies = now;
        entry->count         = 1;
        entry->blocked       = false;
        return;
    }

    entry->count++;

    if (!entry->blocked && entry->count >= USB_ACTIVITY_THRESHOLD) {
        char msg[128];

        entry->blocked = true;

        snprintf(msg, sizeof(msg),
                 "[WARNING] USB VID=0x%04x, PID=0x%04x excessive activity -> removed from whitelist",
                 vid, pid);
        netlink_send_msg(msg);
        printk(KERN_WARNING "PortGuard_kernel: %s\n", msg);
    }
}

/* check if device is marked as blocked by behavior logic */
static bool is_suspicious_and_blocked(__u16 vid, __u16 pid)
{
    struct suspicious_usb *entry = find_suspicious(vid, pid);

    if (!entry)
        return false;
    return entry->blocked;
}

/* ------------------------------------------------------------------
 * 6. Final whitelist decision (raw whitelist + behavior logic)
 * ------------------------------------------------------------------ */

static bool is_device_whitelisted(struct usb_device *dev)
{
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);

    /* if behavior-based logic says "blocked", treat as not whitelisted */
    if (is_suspicious_and_blocked(vid, pid))
        return false;

    return is_device_whitelisted_raw(vid, pid);
}

/* ------------------------------------------------------------------
 * 7. Netlink message send
 * ------------------------------------------------------------------ */

static void netlink_send_msg(const char *message)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = strlen(message) + 1;
    int res;

    if (!nl_sk)
        return;

    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "PortGuard_kernel: nlmsg_new failed\n");
        return;
    }

    /* using NETLINK_USB as nlmsg_type for consistency */
    nlh = nlmsg_put(skb, 0, 0, NETLINK_USB, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        printk(KERN_ERR "PortGuard_kernel: nlmsg_put failed\n");
        return;
    }

    memcpy(nlmsg_data(nlh), message, msg_size);

    res = nlmsg_unicast(nl_sk, skb, USER_PID);
    if (res < 0) {
        printk(KERN_ERR "PortGuard_kernel: nlmsg_unicast failed (%d) to PID %d\n",
               res, USER_PID);
    }
}

/* ------------------------------------------------------------------
 * 8. USB probe: allow/block + record activity
 * ------------------------------------------------------------------ */

static int usb_drive_probe(struct usb_interface *interface,
                           const struct usb_device_id *id)
{
    struct usb_device *dev = interface_to_usbdev(interface);
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);
    char msg[128];
    bool allowed;
    int ret = 0; /* default: block by claiming */

    allowed = is_device_whitelisted(dev);

    /* if initially whitelisted, record activity; it may flip to blocked */
    if (allowed) {
        record_usb_activity(vid, pid);
        allowed = is_device_whitelisted(dev);
    }

    if (allowed) {
        snprintf(msg, sizeof(msg),
                 "[ALLOWED] Whitelisted USB Handed Off: VID=0x%04x, PID=0x%04x",
                 vid, pid);
        netlink_send_msg(msg);
        /* allow real driver to bind */
        ret = -ENODEV;
    } else {
        snprintf(msg, sizeof(msg),
                 "[BLOCKED] Unauthorized USB Blocked: VID=0x%04x, PID=0x%04x",
                 vid, pid);
        netlink_send_msg(msg);
        /* keep claiming the device to block it */
        ret = 0;
    }

    printk(KERN_INFO "PortGuard_kernel: %s\n", msg);
    return ret;
}

/* ------------------------------------------------------------------
 * 9. USB disconnect: notify and optionally record activity
 * ------------------------------------------------------------------ */

static void usb_drive_disconnect(struct usb_interface *interface)
{
    struct usb_device *dev = interface_to_usbdev(interface);
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);
    char msg[128];

    /* if it was originally in the whitelist, treat disconnect as activity */
    if (is_device_whitelisted_raw(vid, pid)) {
        record_usb_activity(vid, pid);
    }

    snprintf(msg, sizeof(msg),
             "USB Device Disconnected: VID=0x%04x, PID=0x%04x",
             vid, pid);
    netlink_send_msg(msg);
    printk(KERN_INFO "PortGuard_kernel: %s\n", msg);
}

/* ------------------------------------------------------------------
 * 10. USB driver structure
 * ------------------------------------------------------------------ */

static struct usb_driver usb_drive_driver = {
    .name       = "PortGuard_kernel",
    .probe      = usb_drive_probe,
    .disconnect = usb_drive_disconnect,
    .id_table   = usb_drive_id_table,
};

/* ------------------------------------------------------------------
 * 11. Module init & exit
 * ------------------------------------------------------------------ */

static int __init hello_init(void)
{
    int result;
    int i;

    printk(KERN_INFO "PortGuard_kernel: USB Security Filter Driver Registered.\n");

    /* init suspicious list (static, but do it explicitly) */
    for (i = 0; i < MAX_SUSPICIOUS_DEVICES; i++) {
        suspicious_list[i].idVendor      = 0;
        suspicious_list[i].idProduct     = 0;
        suspicious_list[i].first_jiffies = 0;
        suspicious_list[i].count         = 0;
        suspicious_list[i].blocked       = false;
    }

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USB, NULL);
    if (!nl_sk) {
        printk(KERN_ERR "PortGuard_kernel: Netlink socket creation failed!\n");
        return -ENOMEM;
    }

    result = usb_register(&usb_drive_driver);
    if (result) {
        printk(KERN_ERR "PortGuard_kernel: Failed to register USB driver: %d\n",
               result);
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
        return result;
    }

    return 0;
}

static void __exit hello_exit(void)
{
    usb_deregister(&usb_drive_driver);

    if (nl_sk) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
    }

    printk(KERN_INFO "PortGuard_kernel: USB Security Filter Driver Unregistered.\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kamatte");
MODULE_DESCRIPTION("Active USB whitelist/blocker with netlink notification and behavior-based whitelist removal");
