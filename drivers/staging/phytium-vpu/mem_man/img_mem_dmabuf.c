// SPDX-License-Identifier: GPL-2.0+

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/device.h>
#include <linux/vmalloc.h>

#include <linux/dma-buf.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>

#include <img_mem_man.h>
#include "img_mem_man_priv.h"

static int trace_physical_pages;

struct buffer_data {
	struct dma_buf *dma_buf;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
};

static int dmabuf_heap_import(struct device *device, struct heap *heap,
				size_t size, enum img_mem_attr attr, int buf_fd,
				struct buffer *buffer)
{
	struct buffer_data *data;
	int ret;

	pr_debug("%s:%d buffer %d (0x%p) buf_fd %d\n", __func__, __LINE__,
		buffer->id, buffer, buf_fd);

	data = kmalloc(sizeof(struct buffer_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
/*
 * dma_buf_get:
 * 每个消费者可以通过文件描述符fd获取共享缓冲区的引用
 * 该函数返回一个dma_buf的引用，同时增加它的refcount，获取缓冲
 * 区应用后，消费者需要将它的设备附着在该缓冲区上，这样可以
 * 让生产者知道设备的寻址限制。
 */
	data->dma_buf = dma_buf_get(buf_fd);
	if (IS_ERR_OR_NULL(data->dma_buf)) {
		pr_err("%s dma_buf_get fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto dma_buf_get_failed;
	}
	pr_debug("%s:%d buffer %d dma_buf %p\n", __func__, __LINE__,
		buffer->id, data->dma_buf);
/*
 * dma_buf_attach:
 * 返回一个attachment的数据结构，该结构会用于scatterlist的操作
 * dma_buf共享框架有一个记录位图，用于管理附着在该共享
 * 缓冲区上的消费者，到这步为止，生产者可以选择不在
 * 实际的存储设备上分配该缓冲区，而是等待消费者申请
 * 共享内存
 */
	data->attach = dma_buf_attach(data->dma_buf, device);
	if (IS_ERR(data->attach)) {
		pr_err("%s dma_buf_attach fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto dma_buf_attach_failed;
	}
/*
 * dma_buf_map_attachment:
 * 消费者发出访问该缓冲区的请求，当消费者想要使用共享
 * 内存进行dma操作，那么它会通过接口dma_buf_map_attachment够访问
 * 缓冲区，在调用map_dma_buf前至少有一个消费者与之关联
 */
	data->sgt = dma_buf_map_attachment(data->attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(data->sgt)) {
		pr_err("%s dma_buf_map_attachment fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto dma_buf_map_failed;
	}

	if (trace_physical_pages) {
		struct scatterlist *sgl = data->sgt->sgl;

		while (sgl) {
			pr_debug("%s:%d phys %#llx length %d\n",
				__func__, __LINE__,
				(unsigned long long)sg_phys(sgl), sgl->length);
			sgl = sg_next(sgl);
		}
	}

	buffer->priv = data;
	return 0;

dma_buf_map_failed:
	dma_buf_detach(data->dma_buf, data->attach);
dma_buf_attach_failed:
	dma_buf_put(data->dma_buf);
dma_buf_get_failed:
	kfree(data);
	return ret;
}

static void dmabuf_heap_free(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *data = buffer->priv;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);
/*
 * dma_buf_unmap_attachment:
 * 消费者通知生产者dma传输结束
 */
	dma_buf_unmap_attachment(data->attach, data->sgt, DMA_BIDIRECTIONAL);

/*
 * dma_buf_detach:
 * 消费者不再使用该共享内存，则脱离该缓冲区
 */
	dma_buf_detach(data->dma_buf, data->attach);
/*
 * dma_buf_put:
 * 消费者返回缓冲区的引用给生产者，即减少缓冲区的refcount
 */
	dma_buf_put(data->dma_buf);
	kfree(data);
}

static int dmabuf_heap_map_um(struct heap *heap, struct buffer *buffer,
				struct vm_area_struct *vma)
{
	struct buffer_data *data = buffer->priv;
	struct scatterlist *sgl;
	unsigned long addr;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);
	pr_debug("%s:%d vm_start %#lx vm_end %#lx size %ld\n",
		__func__, __LINE__,
		vma->vm_start, vma->vm_end, vma->vm_end - vma->vm_start);
/*
 * pgprot_writecombine:
 * 允许写缓冲
 */
	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	sgl = data->sgt->sgl;
	addr = vma->vm_start;
	while (sgl && addr < vma->vm_end) {
		dma_addr_t phys = sg_phys(sgl); /* sg_dma_address ? */
		unsigned long pfn = phys >> PAGE_SHIFT;
		unsigned int len = sgl->length;
		int ret;

		if (vma->vm_end < (addr + len)) {
			unsigned long size = vma->vm_end - addr;

			pr_debug("%s:%d buffer %d (0x%p) truncating len=%x to size=%lx\n",
				__func__, __LINE__,
				buffer->id, buffer, len, size);
			WARN(round_up(size, PAGE_SIZE) != size,
				"VMA size %lx not page aligned\n", size);
			len = size;
		}
		if (trace_physical_pages)
			pr_debug("%s:%d phys %#llx vaddr %#lx length %u\n",
				__func__, __LINE__,
				(unsigned long long)phys, addr, len);
/*
 * remap_pfn_range:
 * 创建页表
 */
		ret = remap_pfn_range(vma, addr, pfn, len, vma->vm_page_prot);
		if (ret)
			return ret; /* TODO: revert on error? */

		addr += len;
		sgl = sg_next(sgl);
	}

	return 0;
}

static int dmabuf_heap_map_km(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *data = buffer->priv;
	struct dma_buf *dma_buf = data->dma_buf;
	int ret;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr) {
		pr_warn("%s called for already mapped buffer %d\n",
			__func__, buffer->id);
		return 0;
	}
/*
 * dma_buf_begin_cpu_access:
 * 处理器在内核空间访问dma_buf对象前，需要通知生产者
 * 生产者确保处理器可以访问这些内存缓冲区，生产者也需要
 * 确定处理器在指定区域及指定方向的访问的一致性，生产者
 * 可以使用访问区域及访问方向来优化cache flushing,该函数可能会
 * 失败，比如在OOM(内存紧缺)的情况下。
 */
	ret = dma_buf_begin_cpu_access(dma_buf, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("%s begin_cpu_access fd %d\n", __func__, buffer->id);
		return ret;
	}
/*
 * dma_buf_vmap:
 * 访问缓冲区
 */
	/* maybe dma_buf_kmap ? */
	buffer->kptr = dma_buf_vmap(dma_buf);
	if (!buffer->kptr) {
		pr_err("%s dma_buf_kmap failed!\n", __func__);
		return -EFAULT;
	}

	pr_debug("%s:%d buffer %d vmap to 0x%p\n", __func__, __LINE__,
		buffer->id, buffer->kptr);
	return 0;
}

static int dmabuf_get_sg_table(struct heap *heap, struct buffer *buffer,
				struct sg_table **sg_table)
{
	struct buffer_data *data = buffer->priv;

	*sg_table = data->sgt;
	return 0;
}

static void dmabuf_heap_destroy(struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);
}

static struct heap_ops dmabuf_heap_ops = {
	.alloc = NULL,
	.import = dmabuf_heap_import,
	.free = dmabuf_heap_free,
	.map_um = dmabuf_heap_map_um,
	.map_km = dmabuf_heap_map_km,
	.get_sg_table = dmabuf_get_sg_table,
	.get_page_array = NULL,
	.sync_cpu_to_dev = NULL, /* TODO */
	.sync_dev_to_cpu = NULL, /* TODO */
	.destroy = dmabuf_heap_destroy,
};

int img_mem_dmabuf_init(const struct heap_config *heap_cfg, struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);

	heap->ops = &dmabuf_heap_ops;
	return 0;
}

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
