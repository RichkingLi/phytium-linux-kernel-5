/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef VXD_COMMON_H
#define VXD_COMMON_H

#include <linux/version.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/list.h>
#include <linux/dcache.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <linux/time.h>

#include <uapi/vxd.h>

#include <img_mem_man.h>

#include "vxd_pvdec_priv.h"


#define VXD_MIN_STREAM_ID 1
#define VXD_MAX_STREAMS_PER_DEV 254
#define VXD_MAX_STREAM_ID (VXD_MIN_STREAM_ID + VXD_MAX_STREAMS_PER_DEV)

struct vxd_state {
	struct vxd_hw_state hw_state;
	uint16_t msg_id_tail;

};

struct vxd_stats {
	struct vxd_hw_boot boot; /* Per boot hw statistics */

	/* The total cumulative time that the device has been powered on
	 * (millisecond resolution)
	 */
	u64 uptime_ms;
	unsigned int mem_usage_last;
};

/* VXD core specific context */
struct vxd_dev {
	struct device *dev;
	struct list_head list; /* Entry in <struct vxd_drv:devices> */
	struct idr streams; /* relation between stream id and <struct vxd_stream> */

	struct mutex mutex;

	struct vxd_core_props props; /* HW properties */
	struct mmu_config mmu_config; /* MMU HW properties */

	struct vxd_dev_fw {
		int buf_id; /* ID of the firmware device buffer */
		struct vxd_fw_hdr *hdr; /* Firmware header */
		const struct firmware *fw; /* Handle acquired from userspace */
	} firmware[VXD_STR_TYPE_MAX];

	uint8_t fw_refcnt; /* Current firmware reference counter */
	uint32_t fw_type;  /* Current type of streams being processed */

	int rendec_buf_id; /* ID of a rendec buffer */

	struct mmu_ctx *mmu_ctx; /* Global/device MMU context to store fw & rendec mappings */
	unsigned int ptd;

	void __iomem *reg_base;
	unsigned int reg_size;

	void *plat_data; /* Platform-specific data */

	struct miscdevice miscdev; /* UM interface */
	void *dbgfs_ctx; /* Debug FS context */

	struct list_head links; /* List of associated <struct vxd_link> */
	/* List of <struct vxd_item> corresponding to
	 * messages submitted to the VXD.
	 * Also called current queue.
	 */
	struct list_head msgs;
	struct list_head pend; /* List of pending <struct vxd_item>s */

	int msg_cnt; /* Counter of messages submitted to VXD. Wraps every VXD_MSG_ID_MASK */

	struct delayed_work dwork; /* Power management and watchdog */
	unsigned long work_sched_at; /* Time the last work has been scheduled at */

	bool hw_on;  /* Current state indicating the core is up & running or not */
	bool hw_dead;  /* Set when the core is unavailable */
	uint32_t emergency; /* Indicates if emergency condition occurred */
	/* Run-time parameters - this is a copy from module params */
	bool keep_hw_on;
	bool fw_upload_dma;
	/* Delay, in ms, between core becomes idle and core is powered off */
	uint32_t hw_pm_delay;
	uint32_t hw_dwr_period;
	uint32_t boot_msleep;
	uint32_t fw_wait_dbg_fifo;

	/* Memory staller configuration */
	uint32_t *memstaller_conf;
	uint8_t  memstaller_size;

	unsigned long pm_start; /* Time, in jiffies, when core became idle */
	unsigned long dwr_start; /* Time, in jiffies, when dwr has been started */

	struct timespec hw_start; /* Time, when core has been powered on */

	struct vxd_stats stats; /* Core statistics */

	struct vxd_state state; /* The actual core state */
	/* HW signatures to be enabled by the firmware. Request
	 * to enable particular signatures is sent to the
	 * firmware in init message.
	 */
	uint32_t hw_crc;

};

/* Link between a userspace process and a particular core */
struct vxd_link {
	struct vxd_dev *vxd; /* Associated device pointer */
	struct list_head list; /* Entry in <struct vxd_dev:links> */

	struct mem_ctx *mem_ctx;

	wait_queue_head_t queue;

	struct list_head items_done; /* Processed queue */

	struct list_head streams; /* Associated streams (struct vxd_stream)*/

	int num_items; /* Number of submitted, not yet returned items */

};

/* Work entity */
struct vxd_item {
	struct list_head list; /* Entry in <struct vxd_link:items_done> OR
				* <struct vxd_dev:msgs>. OR
				* <struct vxd_dev:pend>
				*/
	uint32_t str_id; /* Stream id */
	uint16_t msg_id; /* Stream id */
	uint8_t ttl; /* Time to live */

	struct {
		unsigned destroy:1; /* Item belong to the stream which is
				     * being destroyed
				     */
	};

	struct vxd_fw_msg msg; /* has to be last, it's variable-size! */

};

/* Stream specific context */
struct vxd_stream {
	struct vxd_link *link; /* Associated userspace link */
	struct list_head list; /* Entry in <struct vxd_link:streams> */

	struct mmu_ctx *mmu_ctx; /* MMU context for this stream */
	unsigned int ptd;

	uint32_t id; /* Unique ID */
	uint32_t type; /* vxd_stream_type */
};

/* vxd_core.c */

/* early init of vxd_core (to be called first thing) */
void vxd_core_early_init(void);

int vxd_deinit(void);

int vxd_add_link(struct vxd_dev *vxd, struct vxd_link *link);
void vxd_rm_link(struct vxd_dev *vxd, struct vxd_link *link);
int vxd_add_dev(struct device *dev,
		const struct heap_config heap_configs[], const int heaps,
		void *plat_data, void __iomem *reg_base, unsigned int reg_size);
void vxd_rm_dev(struct device *dev);
int vxd_create_stream(struct vxd_dev *vxd, struct vxd_link *link,
		uint32_t *str_id, uint32_t str_type);
int vxd_destroy_stream(struct vxd_dev *vxd, struct vxd_link *link,
		uint32_t str_id);
int vxd_map_buffer(struct vxd_dev *vxd, struct vxd_link *link,
		   uint32_t str_id, uint32_t buff_id,
		   uint32_t virt_addr, uint32_t map_flags);
int vxd_unmap_buffer(struct vxd_dev *vxd, struct vxd_link *link,
		     uint32_t str_id, uint32_t buff_id);

irqreturn_t vxd_handle_irq(struct device *dev);
irqreturn_t vxd_handle_thread_irq(struct device *dev);

void *vxd_get_plat_data(const struct device *dev);
int vxd_send_msg(struct vxd_dev *vxd, struct vxd_item *item,
		const struct vxd_link *link);

size_t vxd_read_mtx_fifo(struct vxd_dev *vxd, u32 *buf, size_t size);
int vxd_read_mtx_ram(struct vxd_dev *vxd, u32 addr, u32 count,
		u32 *buf, size_t size);
int vxd_read_mtx_status(struct vxd_dev *vxd, u32 *buf, size_t size);
int vxd_setup_memstaller(struct vxd_dev *vxd, u32 *buf, size_t size);
int vxd_force_emergency(struct vxd_dev *vxd, unsigned int val);
int vxd_reload_fws(struct vxd_dev *vxd);

int vxd_check_dev(struct vxd_dev *vxd, unsigned int *enabled);

int vxd_suspend_dev(struct device *dev);
int vxd_resume_dev(struct device *dev);

/* vxd_api.c */
int vxd_api_add_dev(struct device *dev, unsigned int id,
		struct vxd_dev *vxd);
int vxd_api_rm_dev(struct device *dev, struct vxd_dev *vxd);

#endif /* VXD_COMMON_H */

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
