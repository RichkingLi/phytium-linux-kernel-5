//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */
#include <linux/kernel.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/memory.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/jiffies.h>

uint32_t osal_read_timestamp_ms(void)
{
    return jiffies_to_msecs(jiffies);
}

void osal_delay_us(uint32_t us)
{
    udelay(us);
}

void osal_delay_ms(uint32_t ms)
{
    mdelay(ms);
    return;
}

void osal_sleep_ms(uint32_t ms)
{
    msleep(ms);
    return;
}

/*
 * Only can convert low memory & kmap() memory.
 * This require sg list page need mapped by kmap().
 */
uintptr_t osal_virt_to_phys(void *va)
{
    struct page *page = NULL;
    uintptr_t offs    = (uintptr_t)va & (PAGE_SIZE - 1);
    uintptr_t phys    = 0;

    page = kmap_to_page(va);
    phys = page_to_phys(page);
    phys += offs;

    return phys;
}

void *osal_phys_to_virt(uintptr_t pa)
{
    struct page *page = NULL;
    void *va          = NULL;
    uintptr_t offs    = (uintptr_t)pa & (PAGE_SIZE - 1);
    page              = phys_to_page(pa);

    va = page_address(page);

    return (void *)(((uintptr_t)va) + offs);
}
