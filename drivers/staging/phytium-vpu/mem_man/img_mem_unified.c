// SPDX-License-Identifier: GPL-2.0+

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>
#ifdef CONFIG_X86
#include <asm/cacheflush.h>
#endif

#include <img_mem_man.h>
#include "img_mem_man_priv.h"

static int trace_physical_pages;

struct buffer_data {
	struct sg_table *sgt;
	uint64_t *addrs; /* array of physical addresses, upcast to 64-bit */
};

static int unified_alloc(struct device *device, struct heap *heap,
			size_t size, enum img_mem_attr attr,
			struct buffer *buffer)
{
	struct buffer_data *buffer_data;
	int p, pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	int ret;

	buffer_data = kmalloc(sizeof(struct buffer_data), GFP_KERNEL);
	if (!buffer_data)
		return -ENOMEM;

	buffer_data->addrs = kmalloc_array(pages, sizeof(uint64_t), GFP_KERNEL);
	if (!buffer_data->addrs) {
		kfree(buffer_data);
		return -ENOMEM;
	}

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	p = 0;
	while (p < pages) {
		struct page *page;
		dma_addr_t dma_addr;

		page = alloc_page(heap->options.unified.gfp_type);
		if (!page) {
			pr_err("%s alloc_page failed!\n", __func__);
			ret = -ENOMEM;
			goto alloc_page_failed;
		}
		if (trace_physical_pages)
			pr_debug("%s:%d phys %#llx size %lu page_address %p\n",
				__func__, __LINE__,
				(unsigned long long)page_to_phys(page),
				PAGE_SIZE, page_address(page));

		/*
		 * dma_map_page() is probably going to fail if alloc flags are
		 * GFP_HIGHMEM, since it is not mapped to CPU. Hopefully, this
		 * will never happen because memory of this sort cannot be used
		 * for DMA anyway. To check if this is the case, build with
		 * debug, set trace_physical_pages=1 and check if page_address
		 * printed above is NULL
		 */
		dma_addr = dma_map_page(device, page, 0, PAGE_SIZE,
					DMA_BIDIRECTIONAL);
		if (dma_mapping_error(device, dma_addr)) {
			__free_page(page);
			pr_err("%s dma_map_page failed!\n", __func__);
			ret = -EIO;
			goto alloc_page_failed;
		}
		dma_unmap_page(device, dma_addr, PAGE_SIZE, DMA_BIDIRECTIONAL);

#ifdef CONFIG_X86
		set_memory_wc((unsigned long)page_address(page), 1);
#endif
		buffer_data->addrs[p++] = page_to_pfn(page) << PAGE_SHIFT;
	}

	buffer->priv = buffer_data;
	return 0;

alloc_page_failed:
	while (p) {
		struct page *page = pfn_to_page(buffer_data->addrs[p--] >>
			PAGE_SHIFT);

		if (page) {
#ifdef CONFIG_X86
			set_memory_wb((unsigned long)page_address(page), 1);
#endif
			__free_page(page);
		}
	}
	kfree(buffer_data->addrs);
	kfree(buffer_data);
	return ret;
}

static void unified_free(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *buffer_data = buffer->priv;
	int p, pages = (buffer->actual_size + PAGE_SIZE - 1) / PAGE_SIZE;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr) {
		p = 0;
		while (p < pages) {
			dma_addr_t dma_addr = buffer_data->addrs[p++];

			dma_unmap_page(buffer->device, dma_addr, PAGE_SIZE, DMA_FROM_DEVICE);
		}
		pr_debug("%s vunmap 0x%p\n", __func__, buffer->kptr);
		vunmap(buffer->kptr);
	}

	p = 0;
	while (p < pages) {
		struct page *page = pfn_to_page(buffer_data->addrs[p++] >>
			PAGE_SHIFT);
		if (page) {
#ifdef CONFIG_X86
			set_memory_wb((unsigned long)page_address(page), 1);
#endif
			__free_page(page);
		}
	}
	kfree(buffer_data->addrs);
	kfree(buffer_data);
}

static int unified_map_um(struct heap *heap, struct buffer *buffer,
			struct vm_area_struct *vma)
{
	struct buffer_data *buffer_data = buffer->priv;
	unsigned long addr;
	int p, pages = (buffer->actual_size + PAGE_SIZE - 1) / PAGE_SIZE;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);
	pr_debug("%s:%d vm_start %#lx vm_end %#lx size %ld\n",
		__func__, __LINE__,
		vma->vm_start, vma->vm_end, vma->vm_end - vma->vm_start);

//	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	addr = vma->vm_start;
	p = 0;
	while (addr < vma->vm_end && p < pages) {
		phys_addr_t phys = buffer_data->addrs[p++];
		unsigned long pfn = phys >> PAGE_SHIFT;
		int ret;

		if (trace_physical_pages)
			pr_debug("%s:%d phys %#llx vaddr %#lx\n",
				__func__, __LINE__,
				(unsigned long long)phys, addr);

		ret = remap_pfn_range(vma, addr, pfn, PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			return ret; /* TODO: revert on error? */

		addr += PAGE_SIZE;
	}

	return 0;
}

static int unified_map_km(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *buffer_data = buffer->priv;
	int p, num_pages = (buffer->actual_size + PAGE_SIZE - 1) / PAGE_SIZE;
	struct page **pages;
	pgprot_t prot;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr) {
		pr_warn("%s called for already mapped buffer %d\n",
			__func__, buffer->id);
		return 0;
	}

	pages = kmalloc_array(num_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	prot = PAGE_KERNEL;
//	prot = pgprot_writecombine(prot);

	p = 0;
	while (p < num_pages) {
		pages[p] = pfn_to_page(buffer_data->addrs[p] >> PAGE_SHIFT);
		p++;
	}

	buffer->kptr = vmap(pages, num_pages, VM_MAP, prot);
	kfree(pages);
	if (!buffer->kptr) {
		pr_err("%s vmap failed!\n", __func__);
		return -EFAULT;
	}

	p = 0;
	while (p < num_pages) {
		struct page *page = pfn_to_page(buffer_data->addrs[p++] >>
			PAGE_SHIFT);
		dma_addr_t dma_addr = dma_map_page(buffer->device, page, 0,
				PAGE_SIZE, DMA_FROM_DEVICE);
		if (dma_mapping_error(buffer->device, dma_addr)) {
			pr_err("%s dma_map_page failed!\n", __func__);
			vunmap(buffer->kptr);
			return -EFAULT;
		}
	}

	pr_debug("%s:%d buffer %d vmap to 0x%p\n", __func__, __LINE__,
		buffer->id, buffer->kptr);

	return 0;
}

static int unified_get_page_array(struct heap *heap,
					struct buffer *buffer,
					uint64_t **addrs)
{
	struct buffer_data *buffer_data = buffer->priv;

	*addrs = buffer_data->addrs;
	return 0;
}

static void unified_sync_cpu_to_dev(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *buffer_data = buffer->priv;
	int p, pages = (buffer->actual_size + PAGE_SIZE - 1) / PAGE_SIZE;

	if (!buffer->kptr)
		return;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	p = 0;
	while (p < pages) {
		dma_addr_t dma_addr = buffer_data->addrs[p++];

		dma_sync_single_for_device(buffer->device, dma_addr, PAGE_SIZE,
				DMA_TO_DEVICE);
	}
}

static void unified_sync_dev_to_cpu(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *buffer_data = buffer->priv;
	int p, pages = (buffer->actual_size + PAGE_SIZE - 1) / PAGE_SIZE;

	if (!buffer->kptr)
		return;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	p = 0;
	while (p < pages) {
		dma_addr_t dma_addr = buffer_data->addrs[p++];

		dma_sync_single_for_cpu(buffer->device, dma_addr, PAGE_SIZE,
				DMA_TO_DEVICE);
	}
}

/* Variant for allocating with sg chain */
static int unified_alloc_sg(struct device *device, struct heap *heap,
			size_t size, enum img_mem_attr attr,
			struct buffer *buffer)
{
	struct buffer_data *buffer_data;
	struct scatterlist *sgl;
	struct sg_table *sgt;
	int pages;
	int ret;

	buffer_data = kmalloc(sizeof(struct buffer_data), GFP_KERNEL);
	if (!buffer_data)
		return -ENOMEM;

	sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!sgt) {
		ret = -ENOMEM;
		goto priv_data_alloc_failed;
	}

	pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;

	ret = sg_alloc_table(sgt, pages, GFP_KERNEL);
	if (ret)
		goto sg_alloc_table_failed;

	sgl = sgt->sgl;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	while (sgl) {
		struct page *page;
		dma_addr_t dma_addr;

		page = alloc_page(heap->options.unified.gfp_type);
		if (!page) {
			pr_err("%s alloc_page failed!\n", __func__);
			ret = -ENOMEM;
			goto alloc_page_failed;
		}
		if (trace_physical_pages)
			pr_debug("%s:%d phys %#llx size %lu page_address %p\n",
				__func__, __LINE__,
				(unsigned long long)page_to_phys(page),
				PAGE_SIZE, page_address(page));

		/*
		 * dma_map_page() is probably going to fail if alloc flags are
		 * GFP_HIGHMEM, since it is not mapped to CPU. Hopefully, this
		 * will never happen because memory of this sort cannot be used
		 * for DMA anyway. To check if this is the case, build with
		 * debug, set trace_physical_pages=1 and check if page_address
		 * printed above is NULL
		 */
		dma_addr = dma_map_page(device, page, 0, PAGE_SIZE,
					DMA_BIDIRECTIONAL);
		if (dma_mapping_error(device, dma_addr)) {
			__free_page(page);
			pr_err("%s dma_map_page failed!\n", __func__);
			ret = -EIO;
			goto alloc_page_failed;
		}
		dma_unmap_page(device, dma_addr, PAGE_SIZE, DMA_BIDIRECTIONAL);

		sg_set_page(sgl, page, PAGE_SIZE, 0);
#ifdef CONFIG_X86
		set_memory_wc((unsigned long)page_address(page), 1);
#endif
		sgl = sg_next(sgl);
	}
	buffer_data->sgt = sgt;

	buffer->priv = buffer_data;
	return 0;

alloc_page_failed:
	sgl = sgt->sgl;
	while (sgl) {
		struct page *page = sg_page(sgl);

		if (page) {
#ifdef CONFIG_X86
			set_memory_wb((unsigned long)page_address(page), 1);
#endif
			__free_page(page);
		}
		sgl = sg_next(sgl);
	}
	sg_free_table(sgt);
sg_alloc_table_failed:
	kfree(sgt);
priv_data_alloc_failed:
	kfree(buffer_data);
	return ret;
}

static void unified_free_sg(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *buffer_data = buffer->priv;
	struct sg_table *sgt = buffer_data->sgt;
	struct scatterlist *sgl;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr) {
		pr_debug("%s vunmap 0x%p\n", __func__, buffer->kptr);
		dma_unmap_sg(buffer->device, sgt->sgl,
				sgt->orig_nents, DMA_FROM_DEVICE);
		vunmap(buffer->kptr);
	}

	sgl = sgt->sgl;
	while (sgl) {
#ifdef CONFIG_X86
		set_memory_wb((unsigned long)page_address(sg_page(sgl)), 1);
#endif
		__free_page(sg_page(sgl));
		sgl = sg_next(sgl);
	}
	sg_free_table(sgt);
	kfree(sgt);
	kfree(buffer_data);
}

static int unified_map_um_sg(struct heap *heap, struct buffer *buffer,
			struct vm_area_struct *vma)
{
	struct buffer_data *buffer_data = buffer->priv;
	struct sg_table *sgt = buffer_data->sgt;
	struct scatterlist *sgl;
	unsigned long addr;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);
	pr_debug("%s:%d vm_start %#lx vm_end %#lx size %ld\n",
		__func__, __LINE__,
		vma->vm_start, vma->vm_end, vma->vm_end - vma->vm_start);

//	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	sgl = sgt->sgl;
	addr = vma->vm_start;
	while (sgl && addr < vma->vm_end) {
		dma_addr_t phys = sg_phys(sgl); /* sg_dma_address ? */
		unsigned long pfn = phys >> PAGE_SHIFT;
		unsigned int len = sgl->length;
		int ret;

		if (vma->vm_end < (addr + len)) {
			unsigned long size = vma->vm_end - addr;

			pr_debug("%s:%d buffer %d (0x%p) truncating len=%x to size=%lx\n",
					__func__, __LINE__, buffer->id, buffer, len, size);
			WARN(round_up(size, PAGE_SIZE) != size,
				"VMA size %lx not page aligned\n", size);
			len = size;
		}
		if (trace_physical_pages)
			pr_debug("%s:%d phys %#llx vaddr %#lx length %u\n", __func__, __LINE__,
					(unsigned long long)phys, addr, len);

		ret = remap_pfn_range(vma, addr, pfn, len, vma->vm_page_prot);
		if (ret)
			return ret; /* TODO: revert on error? */

		addr += len;
		sgl = sg_next(sgl);
	}

	return 0;
}

static int unified_map_km_sg(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *buffer_data = buffer->priv;
	struct sg_table *sgt = buffer_data->sgt;
	struct scatterlist *sgl = sgt->sgl;
	unsigned int num_pages = sg_nents(sgl);
	struct page **pages;
	pgprot_t prot;
	int ret;
	int i;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__, buffer->id, buffer);

	if (buffer->kptr) {
		pr_warn("%s called for already mapped buffer %d\n", __func__, buffer->id);
		return 0;
	}

	pages = kmalloc_array(num_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	prot = PAGE_KERNEL;
//	prot = pgprot_writecombine(prot);

	i = 0;
	while (sgl) {
		pages[i++] = sg_page(sgl);
		sgl = sg_next(sgl);
	}

	buffer->kptr = vmap(pages, num_pages, VM_MAP, prot);
	kfree(pages);
	if (!buffer->kptr) {
		pr_err("%s vmap failed!\n", __func__);
		return -EFAULT;
	}

	ret = dma_map_sg(buffer->device, sgt->sgl, sgt->orig_nents,
			DMA_FROM_DEVICE);
	if (ret <= 0) {
		pr_err("%s dma_map_sg failed!\n", __func__);
		vunmap(buffer->kptr);
		return -EFAULT;
	}
	pr_debug("%s:%d buffer %d orig_nents %d nents %d\n", __func__, __LINE__,
		buffer->id, sgt->orig_nents, ret);
	sgt->nents = ret;

	pr_debug("%s:%d buffer %d vmap to 0x%p\n", __func__, __LINE__,
		buffer->id, buffer->kptr);

	return 0;
}

static int unified_get_sg_table(struct heap *heap, struct buffer *buffer,
				struct sg_table **sg_table)
{
	struct buffer_data *buffer_data = buffer->priv;
	*sg_table = buffer_data->sgt;
	return 0;
}

static void unified_sync_cpu_to_dev_sg(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *buffer_data = buffer->priv;
	struct sg_table *sgt = buffer_data->sgt;

	if (!buffer->kptr)
		return;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	dma_sync_sg_for_device(buffer->device, sgt->sgl, sgt->orig_nents,
				DMA_TO_DEVICE);
}

static void unified_sync_dev_to_cpu_sg(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *buffer_data = buffer->priv;
	struct sg_table *sgt = buffer_data->sgt;

	if (!buffer->kptr)
		return;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	dma_sync_sg_for_cpu(buffer->device, sgt->sgl, sgt->orig_nents,
				DMA_TO_DEVICE);
}

static void unified_heap_destroy(struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);
}

static struct heap_ops unified_heap_ops = {
	.alloc = unified_alloc,
	.import = NULL,
	.free = unified_free,
	.map_um = unified_map_um,
	.map_km = unified_map_km,
	.get_sg_table = NULL,
	.get_page_array = unified_get_page_array,
	.sync_cpu_to_dev = unified_sync_cpu_to_dev,
	.sync_dev_to_cpu = unified_sync_dev_to_cpu,
	.destroy = unified_heap_destroy,
};

static struct heap_ops unified_heap_ops_sg_chain = {
	.alloc = unified_alloc_sg,
	.import = NULL,
	.free = unified_free_sg,
	.map_um = unified_map_um_sg,
	.map_km = unified_map_km_sg,
	.get_sg_table = unified_get_sg_table,
	.get_page_array = NULL,
	.sync_cpu_to_dev = unified_sync_cpu_to_dev_sg,
	.sync_dev_to_cpu = unified_sync_dev_to_cpu_sg,
	.destroy = unified_heap_destroy,
};

int img_mem_unified_init(const struct heap_config *heap_cfg, struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);

	if (heap_cfg->options.unified.no_sg_chain)
		heap->ops = &unified_heap_ops;
	else
		heap->ops = &unified_heap_ops_sg_chain;
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
