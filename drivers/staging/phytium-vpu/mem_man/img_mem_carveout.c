// SPDX-License-Identifier: GPL-2.0+

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>
#include <linux/genalloc.h>

#include <img_mem_man.h>
#include "img_mem_man_priv.h"

/* 12 bits (4096 bytes) */
#define POOL_ALLOC_ORDER 12

struct heap_data {
	struct gen_pool *pool;
};

struct buffer_data {
	unsigned long addr; /* addr returned by genalloc */
	uint64_t *addrs; /* array of physical addresses, upcast to 64-bit */
};

static int trace_physical_pages;

static int carveout_heap_alloc(struct device *device, struct heap *heap,
			       size_t size, enum img_mem_attr attr,
			       struct buffer *buffer)
{
	struct heap_data *heap_data = heap->priv;
	struct buffer_data *buffer_data;
	phys_addr_t phys_addr;
	size_t pages, page;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		 buffer->id, buffer);

	buffer_data = kmalloc(sizeof(struct buffer_data), GFP_KERNEL);
	if (!buffer_data)
		return -ENOMEM;

	pages = size / PAGE_SIZE;
	buffer_data->addrs = kmalloc_array(pages, sizeof(uint64_t), GFP_KERNEL);
	if (!buffer_data->addrs) {
		kfree(buffer_data);
		return -ENOMEM;
	}

	buffer_data->addr = gen_pool_alloc(heap_data->pool, size);
	if (!buffer_data->addr) {
		pr_err("%s gen_pool_alloc failed!\n", __func__);
		kfree(buffer_data->addrs);
		kfree(buffer_data);
		return -ENOMEM;
	}
	buffer->kptr = (void *)buffer_data->addr;

	phys_addr = gen_pool_virt_to_phys(heap_data->pool, buffer_data->addr);

	page = 0;
	while (page < pages) {
		if (trace_physical_pages)
			pr_debug("%s phys %llx\n",
				 __func__, (unsigned long long)phys_addr);
		buffer_data->addrs[page++] = phys_addr;
		phys_addr += PAGE_SIZE;
	};

	buffer->priv = buffer_data;

	pr_debug("%s buffer %d kptr %p phys %#llx size %zu\n", __func__,
		 buffer->id, buffer->kptr,
		 (unsigned long long)buffer_data->addrs[0], size);
	return 0;
}

static void carveout_heap_free(struct heap *heap, struct buffer *buffer)
{
	struct heap_data *heap_data = heap->priv;
	struct buffer_data *buffer_data = buffer->priv;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		 buffer->id, buffer);

	gen_pool_free(heap_data->pool, buffer_data->addr, buffer->actual_size);
	kfree(buffer_data->addrs);
	kfree(buffer_data);
}

static int carveout_heap_map_um(struct heap *heap, struct buffer *buffer,
			       struct vm_area_struct *vma)
{
	struct buffer_data *buffer_data = buffer->priv;
	unsigned long pfn = *buffer_data->addrs >> PAGE_SHIFT;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		 buffer->id, buffer);
	pr_debug("%s:%d vm_start %#lx vm_end %#lx size %ld\n",
		 __func__, __LINE__,
		 vma->vm_start, vma->vm_end, vma->vm_end - vma->vm_start);

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start, pfn,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static int carveout_heap_map_km(struct heap *heap, struct buffer *buffer)
{
	pr_debug("%s:%d buffer %d (0x%p) kptr 0x%p\n", __func__, __LINE__,
		 buffer->id, buffer, buffer->kptr);

	return 0;
}

static int carveout_heap_get_page_array(struct heap *heap,
					struct buffer *buffer,
					uint64_t **addrs)
{
	struct buffer_data *buffer_data = buffer->priv;

	*addrs = buffer_data->addrs;
	return 0;
}

static void carveout_heap_destroy(struct heap *heap)
{
	struct heap_data *heap_data = heap->priv;

	pr_debug("%s:%d\n", __func__, __LINE__);

	gen_pool_destroy(heap_data->pool);
	kfree(heap_data);
}

static struct heap_ops carveout_heap_ops = {
	.alloc = carveout_heap_alloc,
	.import = NULL,
	.free = carveout_heap_free,
	.map_um = carveout_heap_map_um,
	.map_km = carveout_heap_map_km,
	.get_sg_table = NULL,
	.get_page_array = carveout_heap_get_page_array,
	.sync_cpu_to_dev = NULL,
	.sync_dev_to_cpu = NULL,
	.destroy = carveout_heap_destroy,
};

int img_mem_carveout_init(const struct heap_config *config, struct heap *heap)
{
	struct heap_data *heap_data;
	int ret;

	pr_debug("%s phys %#llx kptr %p\n", __func__,
		 (unsigned long long)config->options.carveout.phys,
		 config->options.carveout.kptr);

	if (config->options.carveout.phys & (PAGE_SIZE-1)) {
		pr_err("%s phys addr (%#llx) is not page aligned!\n", __func__,
		       (unsigned long long)config->options.carveout.phys);
		return -EINVAL;
	}

	if (config->options.carveout.kptr == NULL) {
		pr_err("%s km virt addr is NULL!\n", __func__);
		return -EINVAL;
	}

	if (config->options.carveout.size == 0) {
		pr_err("%s size cannot be zero!\n", __func__);
		return -EINVAL;
	}

	heap_data = kmalloc(sizeof(struct heap_data), GFP_KERNEL);
	if (!heap_data)
		return -ENOMEM;

	heap_data->pool = gen_pool_create(POOL_ALLOC_ORDER, -1);
	if (!heap_data->pool) {
		pr_err("%s gen_pool_create failed\n", __func__);
		ret = -ENOMEM;
		goto pool_create_failed;
	}

	ret = gen_pool_add_virt(heap_data->pool,
				(unsigned long)config->options.carveout.kptr,
				config->options.carveout.phys,
				config->options.carveout.size,
				-1);
	if (ret) {
		pr_err("%s gen_pool_add_virt failed\n", __func__);
		goto pool_add_failed;
	}

	heap->ops = &carveout_heap_ops;
	heap->priv = heap_data;
	return 0;

pool_add_failed:
	gen_pool_destroy(heap_data->pool);
pool_create_failed:
	kfree(heap_data);
	return ret;
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
