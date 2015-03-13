
This patch can be used to dump the whole device tree.

It is said that you can also use this to dump the tree in bootloader:
	(not tested yet)
	> cp.b 0xFFF70000 0x800000 0x200
	> fdt addr 800000
	> fdt print


