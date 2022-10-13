//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#ifndef __TRNGCTL_STAT_REG_H__
#define __TRNGCTL_STAT_REG_H__

#define TRNGCTL_STAT_HW_KEY_VALID_SHIFT 0 /**< AO hw key valid flag */
#define TRNGCTL_STAT_HW_KEY_VALID_WIDTH 1

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __ASSEMBLY__

/**
 * trngctl_stat register definition.
 */
typedef union trngctl_statReg {
    /**
     * bit assignments
     */
    struct { __extension__ uint32_t /**< lsbs... */
        hw_key_valid: 1  /**< AO hw key valid flag */,
        hole0: 31; /**< ...to msbs */
    } bits;

    /**
     * value
     */
    uint32_t val;
} trngctl_statReg_t;

#ifdef WITH_BITFIELD_LOG

#ifndef BITFIELD_LOG
#error "BITFIELD_LOG is not defined"
#endif /* !BITFIELD_LOG */

__attribute__((unused)) static void log_trngctl_stat(uint32_t x)
{
    /**
     * Field by field, extract it, print it, and blank it in x.
     * If x is not empty in the end, it means undocumented bits are set.
     * Then print the indices.
     */
    __attribute__((unused)) uint32_t t;
    BITFIELD_LOG("trngctl_stat: 0x%08x is\n", x);


    t = (x >> TRNGCTL_STAT_HW_KEY_VALID_SHIFT) & ((1U << TRNGCTL_STAT_HW_KEY_VALID_WIDTH) - 1);
    BITFIELD_LOG(" hw_key_valid=0x%x (AO hw key valid flag)\n", t);
    x &= ~(((1U << TRNGCTL_STAT_HW_KEY_VALID_WIDTH) - 1) << TRNGCTL_STAT_HW_KEY_VALID_SHIFT);

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

#define log_trngctl_stat(x) do{}while(0)

#endif /* !WITH_BITFIELD_LOG */

#endif /* !__ASSEMBLY__ */

#ifdef __cplusplus
}
#endif

#endif /* __TRNGCTL_STAT_REG_H__ */
