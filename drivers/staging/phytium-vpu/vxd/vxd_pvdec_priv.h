/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef VXD_PVDEC_PRIV_H
#define VXD_PVDEC_PRIV_H

#include <linux/interrupt.h>
#include <uapi/vxd.h>

#include "vxd_pvdec_regs.h"

struct vxd_boot_poll_params {
	unsigned int msleep_cycles;
};

struct vxd_ena_params {
	struct vxd_boot_poll_params boot_poll;

	size_t fw_buf_size;
	/* VXD's MMU virtual address of a firmware buffer. */
	u32 fw_buf_virt_addr;
	u32 ptd; /* Shifted physical address of PTD */

	/* Required for firmware upload via registers. */
	struct {
		const u8 *buf; /* Firmware blob buffer */

	} regs_data;

	struct {
		unsigned use_dma:1; /* Use DMA or upload via registers. */
		unsigned secure:1;  /* Secure flow indicator. */
		/* Indicates that fw shall use blocking mode when putting logs into debug fifo */
		unsigned wait_dbg_fifo:1;
	};

	/* Structure containing memory staller configuration */
	struct {
		u32 *data;          /* Configuration data array */
		u8 size;            /* Configuration size in dwords */

	} mem_staller;

	uint32_t fwwdt_ms;      /* Firmware software watchdog timeout value */

	uint32_t crc; /* HW signatures to be enabled by firmware */
	uint32_t rendec_addr; /* VXD's virtual address of a rendec buffer */
	uint16_t rendec_size; /* Size of a rendec buffer in 4K pages */
};

/* HW state */
struct vxd_hw_state {
	u32 fw_counter;

	u32 fe_status[VXD_MAX_PIPES];
	u32 be_status[VXD_MAX_PIPES];
	u32 dmac_status[VXD_MAX_PIPES][2]; /* Cover DMA chan 2/3*/

	u32 irq_status;

};

struct vxd_hw_boot {
	/* Core clock frequency measured during the boot of the firmware */
	unsigned int freq_khz;
	/* The mtx timer divider value set during the boot procedure */
	unsigned int timer_div;
	uint64_t upload_us; /* Time spent to boot the firmware */

};

int vxd_pvdec_init(const struct device *dev, void __iomem *reg_base);

int vxd_pvdec_ena(const struct device *dev, void __iomem *reg_base,
		struct vxd_ena_params *ena_params, struct vxd_fw_hdr *hdr,
		struct vxd_hw_boot *boot);

int vxd_pvdec_stop(const struct device *dev, void __iomem *reg_base);

int vxd_pvdec_dis(const struct device *dev, void __iomem *reg_base);

int vxd_pvdec_mmu_flush(const struct device *dev, void __iomem *reg_base);

int vxd_pvdec_send_msg(const struct device *dev, void __iomem *reg_base,
		u32 *msg, size_t msg_size, uint16_t msg_id);

int vxd_pvdec_pend_msg_info(const struct device *dev, void __iomem *reg_base,
		size_t *size, uint16_t *msg_id, bool *not_last_msg);

int vxd_pvdec_recv_msg(const struct device *dev, void __iomem *reg_base,
		u32 *buf, size_t buf_size);

int vxd_pvdec_check_fw_status(const struct device *dev,
		void __iomem *reg_base);

size_t vxd_pvdec_peek_mtx_fifo(const struct device *dev,
		void __iomem *reg_base);

size_t vxd_pvdec_read_mtx_fifo(const struct device *dev, void __iomem *reg_base,
		u32 *buf, size_t size);

irqreturn_t vxd_pvdec_clear_int(void __iomem *reg_base, u32 *irq_status);

int vxd_pvdec_check_irq(const struct device *dev, void __iomem *reg_base,
		u32 irq_status);

int vxd_pvdec_msg_fit(const struct device *dev, void __iomem *reg_base,
		size_t msg_size);

void vxd_pvdec_get_state(const struct device *dev, void __iomem *reg_base,
		u32 num_pipes, struct vxd_hw_state *state);

int vxd_pvdec_get_props(const struct device *dev, void __iomem *reg_base,
		struct vxd_core_props *props);

size_t vxd_pvdec_get_dbg_fifo_size(void __iomem *reg_base);

int vxd_pvdec_dump_mtx_ram(const struct device *dev, void __iomem *reg_base,
		u32 addr, u32 count, u32 *buf);

int vxd_pvdec_dump_mtx_status(const struct device *dev, void __iomem *reg_base,
		u32 *array, u32 array_size);

#endif /* VXD_PVDEC_PRIV_H */
