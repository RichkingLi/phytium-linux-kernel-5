//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#ifndef __OSAL_UTILS_H__
#define __OSAL_UTILS_H__

#include "osal_common.h"

#ifdef __cplusplus
extern "C" {
#endif

OSAL_API uint32_t osal_read_timestamp_ms(void);
OSAL_API void osal_sleep_ms(uint32_t ms);
OSAL_API void osal_delay_ms(uint32_t ms);
OSAL_API void osal_delay_us(uint32_t us);
OSAL_API uintptr_t osal_virt_to_phys(void *va);
OSAL_API void *osal_phys_to_virt(uintptr_t pa);

#ifdef __cplusplus
}
#endif

#endif /* __OSAL_UTILS_H__ */
