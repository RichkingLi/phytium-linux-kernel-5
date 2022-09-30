# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Phytium network device drivers.
#
phytium_macb-y	:= macb_main.o

ifeq ($(CONFIG_PHYTIUM_MACB_USE_HWSTAMP),y)
phytium_macb-y	+= macb_ptp.o
endif

obj-$(CONFIG_PHYTIUM_MACB) += phytium_macb.o
