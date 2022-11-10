// SPDX-License-Identifier: GPL-2.0+

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/device.h>

/*
 * gcc preprocessor defines "linux" as "1".
 * [ http://stackoverflow.com/questions/19210935 ]
 * IMG_KERNEL_ION_HEADER can be <linux/ion.h>, which expands to <1/ion.h>
 */
#undef linux
#include IMG_KERNEL_ION_HEADER

#include <img_mem_man.h>
#include "img_mem_man_priv.h"

static int trace_physical_pages;

struct buffer_data {
	struct ion_client *client;
	struct ion_handle *handle;
	struct sg_table *sgt;
};

static int ion_heap_import(struct device *device, struct heap *heap,
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
	data->client = heap->priv;

	data->handle = ion_import_dma_buf(data->client, buf_fd);
	if (IS_ERR_OR_NULL(data->handle)) {
		pr_err("%s ion_import_dma_buf fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto ion_import_dma_buf_failed;
	}
	pr_debug("%s:%d buffer %d ion_handle %p\n", __func__, __LINE__,
		buffer->id, data->handle);

	data->sgt = ion_sg_table(data->client, data->handle);
	if (IS_ERR(data->sgt)) {
		pr_err("%s ion_sg_table fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto ion_sg_table_failed;
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

ion_sg_table_failed:
	ion_free(data->client, data->handle);
ion_import_dma_buf_failed:
	kfree(data);
	return ret;
}

static void ion_heap_free(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *data = buffer->priv;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr)
		ion_unmap_kernel(data->client, data->handle);

	ion_free(data->client, data->handle);
	kfree(data);
}

static int ion_heap_map_um(struct heap *heap, struct buffer *buffer,
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

		ret = remap_pfn_range(vma, addr, pfn, len, vma->vm_page_prot);
		if (ret)
			return ret; /* TODO: revert on error? */

		addr += len;
		sgl = sg_next(sgl);
	}

	return 0;
}

static int ion_heap_map_km(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *data = buffer->priv;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr) {
		pr_warn("%s called for already mapped buffer %d\n",
			__func__, buffer->id);
		return 0;
	}

	buffer->kptr = ion_map_kernel(data->client, data->handle);
	if (!buffer->kptr) {
		pr_err("%s ion_map_kernel failed!\n", __func__);
		return -EFAULT;
	}

	pr_debug("%s:%d buffer %d map to 0x%p\n", __func__, __LINE__,
		buffer->id, buffer->kptr);
	return 0;
}

static int ion_heap_get_sg_table(struct heap *heap, struct buffer *buffer,
				struct sg_table **sg_table)
{
	struct buffer_data *data = buffer->priv;

	*sg_table = data->sgt;
	return 0;
}

static void ion_heap_destroy(struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);
}

static struct heap_ops ion_heap_ops = {
	.alloc = NULL,
	.import = ion_heap_import,
	.free = ion_heap_free,
	.map_um = ion_heap_map_um,
	.map_km = ion_heap_map_km,
	.get_sg_table = ion_heap_get_sg_table,
	.get_page_array = NULL,
	.sync_cpu_to_dev = NULL, /* TODO */
	.sync_dev_to_cpu = NULL, /* TODO */
	.destroy = ion_heap_destroy,
};

int img_mem_ion_init(const struct heap_config *heap_cfg, struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);

	if (!heap_cfg->options.ion.client) {
		pr_err("%s no ion client defined\n", __func__);
		return -EINVAL;
	}

	heap->ops = &ion_heap_ops;
	heap->priv = heap_cfg->options.ion.client;

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
