//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#include <te_memlist.h>

size_t te_memlist_get_total_len(te_memlist_t *list)
{
    size_t _i = 0;
    size_t total_len = 0;

    for (_i = 0; _i < list->nent; _i++){
        total_len += list->ents[_i].len;
    }
    return total_len;
}

void te_memlist_truncate_from_tail( te_memlist_t *list,
                                    uint8_t *buf,
                                    size_t size,
                                    bool b_copy,
                                    te_ml_bp_t *info )
{
    size_t len = 0;
    int n = 0;
    /*backup original info for recover*/
    info->nent = list->nent;
    if (0 == size) {
        info->len = list->ents[list->nent - 1].len;
        info->ind = list->nent - 1;
        info->offset = list->ents[list->nent - 1].len;
        return;
    }

    for (n = list->nent - 1; n >= 0; n--, list->nent--){
        len = (size > list->ents[n].len) ?
                                list->ents[n].len : size;
        if(b_copy){
            osal_memcpy(buf + size  - len,
                    (uint8_t*)list->ents[n].buf + list->ents[n].len - len,
                    len);
        }

        size -= len;
        /* hit breakpoint */
        if(0 == size){
            info->ind = n;
            info->len = list->ents[n].len;
            info->offset = list->ents[n].len - len;
            if (0 == info->offset) {
                list->nent--;
                info->ind -= 1;
                /**< two cases. case#1 nothing left if this case keep len and offset.
                 *              case#2 something left if this case we need to update
                 *                     the offset and len to the next node of the list.
                 *    if info->ind < 0, nothing left.
                 */
                if (info->ind >= 0) {
                    info->offset = list->ents[info->ind].len;
                    info->len = list->ents[info->ind].len;
                }
            } else {
                list->ents[n].len -= len;
            }
            return;
        }
    }
    /* should never reach here, unless reaminder is gt size of list */
    TE_ASSERT(0);
}

int te_memlist_copy_from_tail( te_memlist_t *list,
                                    uint8_t *buf,
                                    size_t size )
{
    size_t len = 0;
    int n = 0;

    if (!list || !buf || !size) {
        return TE_ERROR_BAD_PARAMS;
    }

    for (n = list->nent - 1; n >= 0; n--){
        len = (size > list->ents[n].len) ?
                                list->ents[n].len : size;
        osal_memcpy(buf + size  - len,
                (uint8_t*)list->ents[n].buf + list->ents[n].len - len,
                len);
        size -= len;
        if(0 == size){
            return TE_SUCCESS;
        }
    }

    return TE_ERROR_BAD_INPUT_LENGTH;
}

void te_memlist_truncate_from_head( te_memlist_t *list,
                                    size_t len,
                                    te_ml_bp_t *info )
{
    size_t offset = 0;
    size_t n = 0;

    info->nent = list->nent;
    for (n = 0; n < list->nent; n++){
        offset += list->ents[n].len;

        if(len <= offset){
            info->len = list->ents[n].len;
            list->ents[n].len -= (offset - len);
            info->offset = list->ents[n].len;
            info->ind = n;
            list->nent = n + 1;

            return;
        }
    }
    /* should never reach here, unless len is gt size of list */
    TE_ASSERT(0);
}

