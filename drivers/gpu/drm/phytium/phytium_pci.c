// SPDX-License-Identifier: GPL-2.0
/* Phytium display drm driver
 *
 * Copyright (C) 2021 Phytium Technology Co., Ltd.
 */

#include <drm/drm_drv.h>
#include <drm/drm_drv.h>
#include <linux/pci.h>
#include "phytium_display_drv.h"
#include "phytium_pci.h"
#include "phytium_dp.h"
#include "phytium_gem.h"
#include "x100_dc.h"
#include "x100_dp.h"
#include "e2000_dc.h"
#include "e2000_dp.h"

int dc_msi_enable;
module_param(dc_msi_enable, int, 0644);
MODULE_PARM_DESC(dc_msi_enable, "Enable DC msi interrupt (0-disabled; 1-enabled; default-0)");

void phytium_pci_vram_hw_init(struct phytium_display_private *priv)
{
	struct phytium_pci_private *pci_priv = to_pci_priv(priv);

	pci_priv->dc_hw_vram_init(priv, priv->pool_phys_addr, priv->pool_size);
}

int phytium_pci_vram_init(struct pci_dev *pdev, struct phytium_display_private *priv)
{
	int ret = 0;

	priv->pool_phys_addr = pci_resource_start(pdev, 2);
	priv->pool_size = pci_resource_len(pdev, 2);
	if ((priv->pool_phys_addr != 0) && (priv->pool_size != 0)) {
		priv->pool_virt_addr = devm_ioremap_wc(&pdev->dev, priv->pool_phys_addr,
						       priv->pool_size);
		if (priv->pool_virt_addr == NULL) {
			DRM_ERROR("pci vram ioremap fail, addr:0x%llx, size:0x%llx\n",
				   priv->pool_phys_addr, priv->pool_size);
			ret = -EINVAL;
			goto failed_ioremap;
		}
		ret = phytium_memory_pool_init(&pdev->dev, priv);
		if (ret)
			goto failed_init_memory_pool;

		priv->mem_state[PHYTIUM_MEM_VRAM_TOTAL] = priv->pool_size;
		priv->support_memory_type = MEMORY_TYPE_VRAM;
		priv->vram_hw_init = phytium_pci_vram_hw_init;
	} else {
		DRM_DEBUG_KMS("not support vram\n");
		priv->pool_virt_addr = NULL;
		priv->mem_state[PHYTIUM_MEM_VRAM_TOTAL] = 0;
		priv->support_memory_type = MEMORY_TYPE_SYSTEM_UNIFIED;
		priv->vram_hw_init = NULL;
	}

	return 0;

failed_init_memory_pool:
	devm_iounmap(&pdev->dev, priv->pool_virt_addr);
failed_ioremap:
	return ret;
}

void phytium_pci_vram_fini(struct pci_dev *pdev, struct phytium_display_private *priv)
{
	if (priv->support_memory_type == MEMORY_TYPE_VRAM) {
		phytium_memory_pool_fini(&pdev->dev, priv);
		devm_iounmap(&pdev->dev, priv->pool_virt_addr);
	}
}

static struct phytium_display_private*
phytium_pci_private_init(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct phytium_display_private *priv = NULL;
	struct phytium_pci_private *pci_priv = NULL;
	struct phytium_device_info *phytium_info = (struct phytium_device_info *)ent->driver_data;
	int i = 0;
	resource_size_t io_addr, io_size;

	pci_priv = devm_kzalloc(&pdev->dev, sizeof(*pci_priv), GFP_KERNEL);
	if (!pci_priv) {
		DRM_ERROR("no memory to allocate for drm_display_private\n");
		goto failed_malloc_priv;
	}

	memset(pci_priv, 0, sizeof(*pci_priv));
	priv = &pci_priv->base;
	phytium_display_private_init(priv, dev);

	memcpy(&(priv->info), phytium_info, sizeof(struct phytium_device_info));
	DRM_DEBUG_KMS("priv->info.num_pipes :%d\n", priv->info.num_pipes);
	priv->info.pipe_mask = ((pdev->subsystem_device >> PIPE_MASK_SHIFT) & PIPE_MASK_MASK);
	priv->info.edp_mask = ((pdev->subsystem_device >> EDP_MASK_SHIFT) & EDP_MASK_MASK);
	priv->info.num_pipes = 0;
	for_each_pipe_masked(priv, i)
		priv->info.num_pipes++;
	if (priv->info.num_pipes == 0) {
		DRM_ERROR("num_pipes is zero, so exit init\n");
		goto failed_init_numpipe;
	}

	io_addr = pci_resource_start(pdev, 0);
	io_size = pci_resource_len(pdev, 0);
	priv->regs = ioremap(io_addr, io_size);
	if (priv->regs == NULL) {
		DRM_ERROR("pci bar0 ioremap fail, addr:0x%llx, size:0x%llx\n", io_addr, io_size);
		goto failed_ioremap;
	}

	priv->irq = pdev->irq;
	if (IS_X100(priv)) {
		pci_priv->dc_hw_vram_init = x100_dc_hw_vram_init;
		priv->dc_hw_clear_msi_irq = x100_dc_hw_clear_msi_irq;
		priv->dc_hw_fb_format_check = x100_dc_hw_fb_format_check;
	} else if (IS_E2000(priv)) {
		pci_priv->dc_hw_vram_init = e2000_dc_hw_vram_init;
		priv->dc_hw_clear_msi_irq = NULL;
		priv->dc_hw_fb_format_check = e2000_dc_hw_fb_format_check;
	}

	return priv;

failed_ioremap:
failed_init_numpipe:
	devm_kfree(&pdev->dev, pci_priv);
failed_malloc_priv:
	return NULL;
}

static void
phytium_pci_private_fini(struct pci_dev *pdev, struct phytium_display_private *priv)
{
	struct phytium_pci_private *pci_priv = to_pci_priv(priv);

	if (priv->regs)
		iounmap(priv->regs);

	devm_kfree(&pdev->dev, pci_priv);
}

static int phytium_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct phytium_display_private *priv = NULL;
	struct drm_device *dev = NULL;
	int ret = 0;

	dev = drm_dev_alloc(&phytium_display_drm_driver, &pdev->dev);
	if (IS_ERR(dev)) {
		DRM_ERROR("failed to allocate drm_device\n");
		return PTR_ERR(dev);
	}
	dev->pdev = pdev;
	pci_set_drvdata(pdev, dev);
	pci_set_master(pdev);
	ret = pci_enable_device(pdev);
	if (ret) {
		DRM_ERROR("pci enbale device fail\n");
		goto failed_enable_device;
	}

	if (dc_msi_enable) {
		ret = pci_enable_msi(pdev);
		if (ret)
			DRM_ERROR("pci enbale msi fail\n");
	}

	dma_set_mask(&pdev->dev, DMA_BIT_MASK(40));

	priv = phytium_pci_private_init(pdev, ent);
	if (priv)
		dev->dev_private = priv;
	else
		goto failed_pci_private_init;

	ret = phytium_pci_vram_init(pdev, priv);
	if (ret) {
		DRM_ERROR("failed to init pci vram\n");
		goto failed_pci_vram_init;
	}

	ret = drm_dev_register(dev, 0);
	if (ret) {
		DRM_ERROR("failed to register drm dev\n");
		goto failed_register_drm;
	}

	phytium_dp_hpd_irq_setup(dev, true);

	return 0;

failed_register_drm:
	phytium_pci_vram_fini(pdev, priv);
failed_pci_vram_init:
	phytium_pci_private_fini(pdev, priv);
failed_pci_private_init:
	if (pdev->msi_enabled)
		pci_disable_msi(pdev);
	pci_disable_device(pdev);
failed_enable_device:
	pci_set_drvdata(pdev, NULL);
	drm_dev_put(dev);

	return -1;
}

static void phytium_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct phytium_display_private *priv = dev->dev_private;

	phytium_dp_hpd_irq_setup(dev, false);
	cancel_work_sync(&priv->hotplug_work);
	drm_dev_unregister(dev);
	phytium_pci_vram_fini(pdev, priv);
	phytium_pci_private_fini(pdev, priv);
	if (pdev->msi_enabled)
		pci_disable_msi(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	drm_dev_put(dev);
}

static void phytium_pci_shutdown(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct phytium_display_private *priv = dev->dev_private;

	priv->display_shutdown(dev);
}

static int phytium_pci_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	struct phytium_display_private *priv = drm_dev->dev_private;
	int ret = 0;

	ret = priv->display_pm_suspend(drm_dev);
	if (ret < 0)
		goto out;

	pci_save_state(pdev);
	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);
	udelay(200);

out:
	return ret;
}

static int phytium_pci_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	struct phytium_display_private *priv = drm_dev->dev_private;
	int ret = 0;

	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	ret = pci_enable_device(pdev);
	if (ret)
		return ret;
	pci_set_master(pdev);

	return priv->display_pm_resume(drm_dev);
}

static const struct dev_pm_ops phytium_pci_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(phytium_pci_pm_suspend, phytium_pci_pm_resume)
};

static const struct phytium_device_info x100_info = {
	.platform_mask = BIT(PHYTIUM_PLATFORM_X100),
	.total_pipes = 3,
	.crtc_clock_max = X100_DC_PIX_CLOCK_MAX,
	.hdisplay_max = x100_DC_HDISPLAY_MAX,
	.vdisplay_max = X100_DC_VDISPLAY_MAX,
	.address_mask = X100_DC_ADDRESS_MASK,
	.backlight_max = X100_DP_BACKLIGHT_MAX,
};

static const struct phytium_device_info e2000_info = {
	.platform_mask = BIT(PHYTIUM_PLATFORM_E2000),
	.total_pipes = 2,
	.crtc_clock_max = E2000_DC_PIX_CLOCK_MAX,
	.hdisplay_max = E2000_DC_HDISPLAY_MAX,
	.vdisplay_max = E2000_DC_VDISPLAY_MAX,
	.address_mask = E2000_DC_ADDRESS_MASK,
	.backlight_max = E2000_DP_BACKLIGHT_MAX,
};

static const struct pci_device_id phytium_display_pci_ids[] = {
	{ PCI_VDEVICE(PHYTIUM, 0xdc22), (kernel_ulong_t)&x100_info },
	{ PCI_VDEVICE(PHYTIUM, 0xdc3e), (kernel_ulong_t)&e2000_info },
	{ /* End: all zeroes */ }
};
MODULE_DEVICE_TABLE(pci, phytium_display_pci_ids);

struct pci_driver phytium_pci_driver = {
	.name = "phytium_display_pci",
	.id_table = phytium_display_pci_ids,
	.probe = phytium_pci_probe,
	.remove = phytium_pci_remove,
	.shutdown = phytium_pci_shutdown,
	.driver.pm = &phytium_pci_pm_ops,
};
