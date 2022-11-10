// SPDX-License-Identifier: GPL-2.0+
/*
 * Phytium VPU Driver
 *
 * Copyright (C) 2022 Phytium Technology Co., Ltd.
 */

#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/io.h>
#include <linux/pm.h>
#include <linux/pci.h>

#include <img_mem_man.h>
#include "vxd_common.h"
#include "vxd_plat.h"

#define DEVICE_NAME "vxd"

static unsigned int use_vpu_videomem;
module_param(use_vpu_videomem, uint, 0440);
MODULE_PARM_DESC(use_vpu_videomem, "Use VPU VideoMem");

const unsigned long vxd_plat_poll_udelay = 100;

static struct heap_config pci_heap_configs[] = {
	{
		.type = IMG_MEM_HEAP_TYPE_UNIFIED,
		.options.unified = {
			.gfp_type = GFP_KERNEL | __GFP_ZERO,
		},
		.to_dev_addr = NULL,
	},

	{
		.type = IMG_MEM_HEAP_TYPE_DMABUF,
		.to_dev_addr = NULL,
	},
};


static struct heap_config pci_heap_videomem_configs[] = {
	{
		.type = IMG_MEM_HEAP_TYPE_CARVEOUT,
	},
};

static irqreturn_t pci_plat_thread_irq(int irq, void *dev_id)
{
	struct platform_device *pdev = (struct platform_device *)dev_id;

	return vxd_handle_thread_irq(&pdev->dev);
}

static irqreturn_t pci_plat_isrcb(int irq, void *dev_id)
{
	struct platform_device *pdev = (struct platform_device *)dev_id;

	if (!pdev)
		return IRQ_NONE;

	return vxd_handle_irq(&pdev->dev);
}

static int vxd_platform_probe(struct platform_device *pdev)
{
	int ret, reg_size;
	void __iomem *reg_addr;
	struct resource *res;
	struct resource *res2;
	int irq;

	struct device *dev = &pdev->dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	reg_size = resource_size(res);
	reg_addr = devm_ioremap(dev, res->start, reg_size);
	if (IS_ERR(reg_addr))
		dev_err(dev, "devm_ioremap failed start:0x%llx\n", res->start);

	if (dev->dma_mask) {
		dev_info(dev, "dev->dma_mask:%p %#llx\n", dev->dma_mask, *dev->dma_mask);
	} else {
		dev_info(dev, "mask unset, setting coherent\n");
		dev->dma_mask = &dev->coherent_dma_mask;
	}

	if (dma_set_mask_and_coherent(dev, 0xFFFFFFFF))
		pr_warn("failed to set 32-bit dma\n");

	if (use_vpu_videomem) {
		res2 = platform_get_resource(pdev, IORESOURCE_MEM, 2);
		pci_heap_videomem_configs[0].options.carveout.phys = res2->start;
		pci_heap_videomem_configs[0].options.carveout.size = resource_size(res2);
		pci_heap_videomem_configs[0].options.carveout.kptr = devm_ioremap(
				&pdev->dev,
				pci_heap_videomem_configs[0].options.carveout.phys,
				pci_heap_videomem_configs[0].options.carveout.size);

		writel((res2->start) >> 22, reg_addr + 0x10018);
		writel(0x80000000 + (resource_size(res2) >> 22), reg_addr + 0x1001c);
		writel(0x8200, reg_addr + 0x10020);

		ret = vxd_add_dev(dev, pci_heap_videomem_configs,
				sizeof(pci_heap_videomem_configs)/sizeof(struct heap_config),
				NULL, reg_addr, reg_size);
	} else
		ret = vxd_add_dev(dev, pci_heap_configs,
				sizeof(pci_heap_configs)/sizeof(struct heap_config),
				NULL, reg_addr, reg_size);

	if (ret) {
		dev_err(dev, "failed to initialize driver core!\n");
		goto out_add_dev;
	}

	irq = platform_get_irq(pdev, 0);
	ret = devm_request_threaded_irq(dev, irq, &pci_plat_isrcb,
		&pci_plat_thread_irq, IRQF_SHARED, DEVICE_NAME, pdev);
	if (ret) {
		dev_err(dev, "failed to request irq\n");
		goto out_irq;
	}
	return ret;

out_irq:
	vxd_rm_dev(dev);
out_add_dev:
	devm_iounmap(dev, reg_addr);

	return ret;
}

static int vxd_platform_remove(struct platform_device *pdev)
{
	vxd_rm_dev(&pdev->dev);

	return 0;
}

static int vxd_plat_suspend(struct device *dev)
{
	struct platform_device *ofdev =
		container_of(dev, struct platform_device, dev);
	int ret = 0;

	/* Wait for completion of core activities */
	ret = vxd_suspend_dev(dev);
	if (ret)
		dev_err(&ofdev->dev, "failed to suspend core hw!\n");

	return ret;
}

static int vxd_plat_resume(struct device *dev)
{
	struct platform_device *ofdev =
		container_of(dev, struct platform_device, dev);
	int ret = 0;

	ret = vxd_resume_dev(dev);
	if (ret)
		dev_err(&ofdev->dev, "failed to resume core hw!\n");

	return ret;
}

static UNIVERSAL_DEV_PM_OPS(vxd_pm_pci_ops,
		vxd_plat_suspend, vxd_plat_resume, NULL);

const struct of_device_id vxd_of_id_table[] = {
	{
		.compatible = "phytium,vpu",
	},
	{},
};

struct platform_driver vxd_platform_drv = {
	.probe  = vxd_platform_probe,
	.remove = vxd_platform_remove,
	.driver = {
		.name   = "d5500-vxd",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(vxd_of_id_table),
		.pm = &vxd_pm_pci_ops,
	},
};

MODULE_DEVICE_TABLE(of, vxd_of_id_table);

int vxd_plat_init(void)
{
	int ret = 0;

	ret = platform_driver_register(&vxd_platform_drv);
	if (ret) {
		pr_err("failed to register VXD driver!\n");
		return ret;
	}

	return 0;
}

int vxd_plat_deinit(void)
{
	int ret;

	/* Unregister the driver from the OS */
	platform_driver_unregister(&vxd_platform_drv);

	ret = vxd_deinit();
	if (ret)
		pr_err("VXD driver deinit failed\n");

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
