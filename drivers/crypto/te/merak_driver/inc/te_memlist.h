//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#ifndef __TRUSTENGINE_MEMLIST_H__
#define __TRUSTENGINE_MEMLIST_H__

#include <te_common.h>


#ifdef __cplusplus
extern "C" {
#endif

#ifndef __ASSEMBLY__

/**
 * memory entry structure
 */
typedef struct te_mement {
    void *buf;
    size_t len;
} te_mement_t;

/**
 * memory list structure
 */
typedef struct te_memlist {
    te_mement_t *ents;
    uint32_t nent;               /**< number of entries */
} te_memlist_t;

/**
 * memory list break point structure
 */
typedef struct te_ml_bp{
    size_t nent;   /**< original list's number of entries */
    int ind;       /**< node's index of the break point */
    size_t len;    /**< length of break point's node */
    size_t offset; /**< offset of break point's node */
} te_ml_bp_t;

/**
 * \brief           This function gets the total length of a memory list.
 * \param[in] list  The memory list.
 * \return          The totoal length of the memory list.
 */
size_t te_memlist_get_total_len(te_memlist_t *list);

/**
 * \brief                This function truancates a memory list from tail.
 * \param[in] list       The memory list to be truncated,
 *                       mandatory if b_copy is true.
 * \param[out] buf       Buf to hold truncated data if b_copy is true,
 *                       mandatory if b_copy is true.
 * \param[in] remainder  Size of data to be truncated.
 * \param[in] b_copy     Save truncated data or not, \p true save the data to buf,
 *                       \p false skip saving.
 * \param[out] info      Object to hold break point's info.
 * \return      none
 */
void te_memlist_truncate_from_tail( te_memlist_t *list,
                                    uint8_t *buf,
                                    size_t remainder,
                                    bool b_copy,
                                    te_ml_bp_t *info );

/**
 * \brief            This function truancates a memory list from head.
 * \param[in] list   The memory list to be truncated.
 * \param[in] len    Size of data to be truncated.
 * \param[out] info  Object to hold break point's info.
 * \return   none.
 */
void te_memlist_truncate_from_head( te_memlist_t *list,
                                    size_t len,
                                    te_ml_bp_t *info );

/**
 * \brief                This function copies data from a memory list from tail.
 * \param[in] list       The memory list to be copied.
 * \param[out] buf       Buf to hold the data.
 * \param[in] size       Size of data to be copied.
 * \return      \c TE_SUCCESS on success, others failed.
 */
int te_memlist_copy_from_tail( te_memlist_t *list,
                                    uint8_t *buf,
                                    size_t size );
#endif /* !__ASSEMBLY__ */

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTENGINE_MEMLIST_H__ */
