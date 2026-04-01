# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_SPARKLINK)	+= sparklink.o

sparklink-y := sparklink_core.o
sparklink-y += sle_usb_ffi.o
sparklink-y += sle_serdev_ffi.o
sparklink-y += sle_crypto_ffi.o
sparklink-$(CONFIG_SPARKLINK_GENL) += sparklink_genl.o
