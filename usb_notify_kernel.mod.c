#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x30b0617d, "init_net" },
	{ 0x8ed16b31, "__netlink_kernel_create" },
	{ 0x47886e07, "usb_register_notify" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x47886e07, "usb_unregister_notify" },
	{ 0x53dd8282, "netlink_kernel_release" },
	{ 0x9479a1e8, "strnlen" },
	{ 0x61e00829, "__alloc_skb" },
	{ 0x7dad1f18, "__nlmsg_put" },
	{ 0xa53f4e29, "memcpy" },
	{ 0x2cd7744b, "netlink_unicast" },
	{ 0x40a621c5, "snprintf" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0xd272d446, "__fentry__" },
	{ 0xe8213e80, "_printk" },
	{ 0xd268ca91, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x30b0617d,
	0x8ed16b31,
	0x47886e07,
	0xd272d446,
	0x47886e07,
	0x53dd8282,
	0x9479a1e8,
	0x61e00829,
	0x7dad1f18,
	0xa53f4e29,
	0x2cd7744b,
	0x40a621c5,
	0xd272d446,
	0xe54e0a6b,
	0xd272d446,
	0xe8213e80,
	0xd268ca91,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"init_net\0"
	"__netlink_kernel_create\0"
	"usb_register_notify\0"
	"__x86_return_thunk\0"
	"usb_unregister_notify\0"
	"netlink_kernel_release\0"
	"strnlen\0"
	"__alloc_skb\0"
	"__nlmsg_put\0"
	"memcpy\0"
	"netlink_unicast\0"
	"snprintf\0"
	"__stack_chk_fail\0"
	"__fortify_panic\0"
	"__fentry__\0"
	"_printk\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "21FDFE724E9CDE12B3288C0");
