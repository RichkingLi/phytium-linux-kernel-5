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
 * ÿ�������߿���ͨ���ļ�������fd��ȡ��������������
 * �ú�������һ��dma_buf�����ã�ͬʱ��������refcount����ȡ����
 * ��Ӧ�ú���������Ҫ�������豸�����ڸû������ϣ���������
 * ��������֪���豸��Ѱַ���ơ�
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
 * ����һ��attachment�����ݽṹ���ýṹ������scatterlist�Ĳ���
 * dma_buf��������һ����¼λͼ�����ڹ������ڸù���
 * �������ϵ������ߣ����ⲽΪֹ�������߿���ѡ����
 * ʵ�ʵĴ洢�豸�Ϸ���û����������ǵȴ�����������
 * �����ڴ�
 */
	data->attach = dma_buf_attach(data->dma_buf, device);
	if (IS_ERR(data->attach)) {
		pr_err("%s dma_buf_attach fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto dma_buf_attach_failed;
	}
/*
 * dma_buf_map_attachment:
 * �����߷������ʸû����������󣬵���������Ҫʹ�ù���
 * �ڴ����dma��������ô����ͨ���ӿ�dma_buf_map_attachment������
 * ���������ڵ���map_dma_bufǰ������һ����������֮����
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
 * ������֪ͨ������dma�������
 */
	dma_buf_unmap_attachment(data->attach, data->sgt, DMA_BIDIRECTIONAL);

/*
 * dma_buf_detach:
 * �����߲���ʹ�øù����ڴ棬������û�����
 */
	dma_buf_detach(data->dma_buf, data->attach);
/*
 * dma_buf_put:
 * �����߷��ػ����������ø������ߣ������ٻ�������refcount
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
 * ����д����
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
 * ����ҳ��
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
 * ���������ں˿ռ����dma_buf����ǰ����Ҫ֪ͨ������
 * ������ȷ�����������Է�����Щ�ڴ滺������������Ҳ��Ҫ
 * ȷ����������ָ������ָ������ķ��ʵ�һ���ԣ�������
 * ����ʹ�÷������򼰷��ʷ������Ż�cache flushing,�ú������ܻ�
 * ʧ�ܣ�������OOM(�ڴ��ȱ)������¡�
 */
	ret = dma_buf_begin_cpu_access(dma_buf, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("%s begin_cpu_access fd %d\n", __func__, buffer->id);
		return ret;
	}
/*
 * dma_buf_vmap:
 * ���ʻ�����
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
