#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/types.h> 


struct allowed_usb_device {
    __u16 idVendor;
    __u16 idProduct;
};

static const struct allowed_usb_device whitelist[] = {
    { 0x0781, 0x5591 }, // 기존 코드의 SanDisk USB (예시용) 

};

static const struct usb_device_id usb_drive_id_table[] = {
{
    .match_flags = USB_DEVICE_ID_MATCH_INT_CLASS, 
    .bInterfaceClass = USB_CLASS_MASS_STORAGE,
},
{}
};
MODULE_DEVICE_TABLE(usb, usb_drive_id_table);

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

static int usb_drive_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    struct usb_device *dev = interface_to_usbdev(interface);
    __u16 vid = le16_to_cpu(dev->descriptor.idVendor);
    __u16 pid = le16_to_cpu(dev->descriptor.idProduct);

    // 화이트리스트 검사 수행
    if (is_device_whitelisted(dev)) {
        /*
         * [허용 로직]
         * - 화이트리스트에 있으므로 이 드라이버는 장치를 처리하지 않음
         * - 'return -ENODEV'를 통해 커널에게 "이 장치는 내 것이 아님"을 알림
         * - 커널은 이어서 진짜 'usb-storage' 드라이버를 찾아 장치를 바인딩함
         * - 장치가 정상적으로 마운트되고 사용 가능해짐.
         */
        printk(KERN_INFO "kamatte@ubuntu: [ALLOWED] Whitelisted USB drive detected. VID:0x%04x, PID:0x%04x. Handing off.\n", vid, pid);
        return -ENODEV;
    } else {
        /*
         * [차단 로직]
         * - 화이트리스트에 없으므로 이 드라이버가 장치를 선점(claim)함.
         * - 'return 0'을 통해 커널에게 "이 장치는 내 것임"을 알림.
         * - 이 드라이버는 장치에 대해 아무런 작업을 하지 않으므로
         * 'usb-storage' 드라이버가 바인딩되지 못함
         * - 장치가 시스템에 등록되지만 마운트되지 않아 사용 불가 상태가 됨
         */
        printk(KERN_INFO "kamatte@ubuntu: [BLOCKED] Unauthorized USB drive detected! VID:0x%04x, PID:0x%04x. Claiming interface to block.\n", vid, pid);
        return 0; // 로그에 미허용 usb 감지 및 vid 및 pid 표시
    }
}


static void usb_drive_disconnect(struct usb_interface *interface)
{
    struct usb_device *dev = interface_to_usbdev(interface);
    printk(KERN_INFO "kamatte@ubuntu: [BLOCKED] Unauthorized USB drive disconnected. VID:0x%04x, PID:0x%04x\n",
        le16_to_cpu(dev->descriptor.idVendor),
        le16_to_cpu(dev->descriptor.idProduct));
}

// --- 기존 코드와 동일 ---
static struct usb_driver usb_drive_driver = {
    .name = "PortGuard_kernel", 
    .probe = usb_drive_probe,
    .disconnect = usb_drive_disconnect,
    .id_table = usb_drive_id_table,
};

static int __init hello_init(void)
{
    int result;
    result = usb_register(&usb_drive_driver);
    if (result) {
        printk(KERN_ERR "kamatte@ubuntu: Failed to register USB security driver: %d\n", result);
    } else {
        printk(KERN_INFO "kamatte@ubuntu: USB Security Filter Driver Registered.\n");
    }
    return result;
}
static void __exit hello_exit(void)
{
    usb_deregister(&usb_drive_driver);
    printk(KERN_INFO "kamatte@ubuntu: USB Security Filter Driver Unregistered.\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kamatte");
MODULE_DESCRIPTION("Active USB Whitelist/Blocker Module");
