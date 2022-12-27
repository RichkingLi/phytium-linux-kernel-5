# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Phytium Video Processor Unit
#

ccflags-y += -I$(srctree)/drivers/staging/phytium-vpu/include \
             -I$(srctree)/drivers/staging/phytium-vpu/mem_man/imgmmu/imgold \
             -I$(srctree)/drivers/staging/phytium-vpu/mem_man/imgmmu/mmulib \

ccflags-y += -DIMG_KERNEL_MODULE

ifdef CONFIG_ION
# detect ION header in Linux Kernel tree
# srctree is needed here for kernels built with separate object dir (O=)
ifneq ($(wildcard $(srctree)/include/linux/ion.h),)
# some kernel trees have this non-standard path
ccflags-y += -DIMG_KERNEL_ION_HEADER="<linux/ion.h>"
else
# this is the default location
# the vanilla linux kernel does not export ion.h to include/linux
# adding -I to the entire directory would expose many internal header files
# so we use this somewhat ugly hack to use only this one with full path
# realpath is needed to expand full path, some kernel trees set srctree to .
ccflags-y += -DIMG_KERNEL_ION_HEADER="<$(realpath $(srctree))/drivers/staging/android/ion/ion.h>"
endif
endif # CONFIG_ION

obj-$(CONFIG_VIDEO_PHYTIUM_VPU) += phytium_vpu_mem.o

phytium_vpu_mem-objs := img_mem_man.o \
                img_mem_unified.o \
                img_mem_secure.o \
                imgmmu/imgmmu.o \
                imgmmu/kernel_heap.o

phytium_vpu_mem-$(CONFIG_GENERIC_ALLOCATOR) += img_mem_carveout.o
phytium_vpu_mem-$(CONFIG_DMA_SHARED_BUFFER) += img_mem_dmabuf.o
phytium_vpu_mem-$(CONFIG_ION) += img_mem_ion.o
