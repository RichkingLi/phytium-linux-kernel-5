# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Phytium Video Processor Unit
#

ccflags-y += -I$(srctree)/drivers/staging/phytium-vpu/include
ccflags-$(CONFIG_BUS_MASTERING) += -DFPGA_BUS_MASTERING

obj-$(CONFIG_VIDEO_PHYTIUM_VPU) += phytium_vpu_vxd.o

phytium_vpu_vxd-objs := vxd_core.o \
            vxd_api.o \
            vxd_pvdec.o \
            vxd_debugfs.o \
            vxd_phytium_platform.o
