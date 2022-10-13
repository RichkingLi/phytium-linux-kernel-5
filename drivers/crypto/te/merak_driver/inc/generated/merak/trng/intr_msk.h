//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#ifndef __TRNG_INTR_MSK_REG_H__
#define __TRNG_INTR_MSK_REG_H__

#define TRNG_INTR_MSK_FILL_DONE_SHIFT 0
#define TRNG_INTR_MSK_FILL_DONE_WIDTH 1

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __ASSEMBLY__

/**
 * trng_intr_msk register definition.
 */
typedef union trng_intr_mskReg {
    /**
     * bit assignments
     */
    struct { __extension__ uint32_t /**< lsbs... */
        fill_done: 1,
        hole0: 31; /**< ...to msbs */
    } bits;

    /**
     * value
     */
    uint32_t val;
} trng_intr_mskReg_t;

#ifdef WITH_BITFIELD_LOG

#ifndef BITFIELD_LOG
#error "BITFIELD_LOG is not defined"
#endif /* !BITFIELD_LOG */

__attribute__((unused)) static void log_trng_intr_msk(uint32_t x)
{
    /**
     * Field by field, extract it, print it, and blank it in x.
     * If x is not empty in the end, it means undocumented bits are set.
     * Then print the indices.
     */
    __attribute__((unused)) uint32_t t;
    BITFIELD_LOG("trng_intr_msk: 0x%08x is\n", x);


    t = (x >> TRNG_INTR_MSK_FILL_DONE_SHIFT) & ((1U << TRNG_INTR_MSK_FILL_DONE_WIDTH) - 1);
    BITFIELD_LOG(" fill_done=0x%x\n", t);
    x &= ~(((1U << TRNG_INTR_MSK_FILL_DONE_WIDTH) - 1) << TRNG_INTR_MSK_FILL_DONE_SHIFT);

    if (x) {
        int i = 0;
        BITFIELD_LOG(" (Unknown :");
        while (x) {
            if (x & 1) {
                BITFIELD_LOG(" %d", i);
            }
            x >>= 1;
            i++;
        }
        BITFIELD_LOG(")\n");
    }

    BITFIELD_LOG("\n");
}

#else  /* WITH_BITFIELD_LOG */

#define log_trng_intr_msk(x) do{}while(0)

#endif /* !WITH_BITFIELD_LOG */

#endif /* !__ASSEMBLY__ */

#ifdef __cplusplus
}
#endif

#endif /* __TRNG_INTR_MSK_REG_H__ */
