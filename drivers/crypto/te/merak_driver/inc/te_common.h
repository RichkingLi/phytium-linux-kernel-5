//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#ifndef __TRUSTENGINE_COMMON_H__
#define __TRUSTENGINE_COMMON_H__

#include "osal_common.h"
#include "te_defines.h"
#include "te_endian.h"
#include "osal_assert.h"
#include "osal_atomic.h"
#include "osal_cache.h"
#include "osal_interrupt.h"
#include "osal_log.h"
#include "osal_mem.h"
#include "osal_mutex.h"
#include "osal_sem.h"
#include "osal_string.h"
#include "osal_utils.h"
#include "osal_completion.h"
#include "osal_spin_lock.h"
#include "osal_mem_barrier.h"
#include "osal_thread.h"
#include "utils_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __ASSEMBLY__

#ifndef offsetof
/**
 * offsetof - get the offset a member of a structure
 * @TYPE:       the type of the struct.
 * @MEMBER:     the name of the member within the struct.
 *
 */
#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)

#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                              \
    void *__mptr = (void *)(ptr);                                       \
    ((type *)((unsigned long)__mptr - offsetof(type, member))); })

#endif

#ifndef ARRAY_SIZE
/**
 * ARRAY_SIZE - number of elements in an array
 * @a:          array name.
 */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#ifndef ROUND_UP
/**
 * ROUND_UP - round up
 * @o:          operand.
 * @a:          alignement, must power of two.
 */
#define ROUND_UP(o, a) (((o) + (a) - 1) & ~((a) - 1))
#endif

#ifndef ROUND_DN
/**
 * ROUND_DN - round down
 * @o:          operand.
 * @a:          alignement, must power of two.
 */
#define ROUND_DN(o, a) ((o) & ~((a) - 1))
#endif

#ifndef SET_BITS
/**
 * SET_BITS - set bit[\p s, \p s + \p w] to \p nv for value \p v.
 * @v:          output value.
 * @s:          the field shift value.
 * @w:          the field width.
 * @nv:         new value.
 */
#define SET_BITS(v, s, w, nv) do {                \
    (v) &= ~(((0x1 << (w)) - 1) << (s));          \
    (v) |= ((nv) & ((0x1 << (w)) - 1)) << (s);    \
} while(0)
#endif

#ifndef GET_BITS
/**
 * GET_BITS - get bit[\p s,\p s + \p w] from value \p v.
 * @v:          input value.
 * @s:          the field shift value.
 * @w:          the field width.
 */
#define GET_BITS(v, s, w) (((v) >> (s)) & ((1 << (w)) - 1))
#endif

#ifndef TE_ASSERT
#define TE_ASSERT(cond)                                                     \
    do {                                                                    \
        if (!(cond)) {                                                      \
            OSAL_LOG_ERR("ASSERT !%s +%d !%s\n", __func__, __LINE__, #cond);\
            while(true) ;                                                   \
        }                                                                   \
    }while(0)
#endif

#ifndef TE_ASSERT_MSG
#define TE_ASSERT_MSG(cond, fmt, ...)                                   \
    do {                                                                \
        if (!(cond)) {                                                  \
            OSAL_LOG_ERR("%s +%d !\n" fmt, __func__, __LINE__,          \
                                        ##__VA_ARGS__);                 \
            while(true) ;                                               \
        }                                                               \
    }while(0)
#endif

#ifndef __te_unused
/**
 * __te_unused - Mark variable possibly unused.
 */
#define __te_unused __attribute__((unused))
#endif

#ifndef __te_dma_aligned
/**
 * __te_dma_aligned - Mark variable keep aligned.
 */
#define TE_DMA_ALIGNED    OSAL_CACHE_LINE_SIZE
#define __te_dma_aligned    __attribute__((aligned(TE_DMA_ALIGNED)))
#endif

#endif /* !__ASSEMBLY__ */

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTENGINE_COMMON_H__ */
