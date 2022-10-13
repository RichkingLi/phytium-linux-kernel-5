//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#ifndef __TRUSTENGINE_GHASH_H__
#define __TRUSTENGINE_GHASH_H__

#include "te_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __ASSEMBLY__

/**
 * GHash context structure
 */
typedef struct te_ghash_ctx {
    te_crypt_ctx_t *crypt;
} te_ghash_ctx_t;

/**
 * \brief           This function gets the private ctx of a GHASH ctx.
 * \param[in] ctx   The GHASH context.
 * \return          The private context pointer.
 */
static inline void* ghash_priv_ctx(te_ghash_ctx_t* ctx)
{
    return crypt_priv_ctx(ctx->crypt);
}

/**
 * \brief           This function initializes the GHASH context \p ctx.
 * \param[out] ctx  The GHASH context.
 * \param[in] hdl   The driver handler.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_init( te_ghash_ctx_t *ctx, te_drv_handle hdl );

/**
 * \brief           This function withdraws the GHASH context \p ctx.
 * \param[in] ctx   The GHASH context.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_free( te_ghash_ctx_t *ctx );

/**
 * \brief           This function sets up the user key for the specified
 *                  GHASH context \p ctx.
 * \param[in] ctx   The GHASH context.
 * \param[in] key   The buffer holding the 128-bit H key.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_setkey( te_ghash_ctx_t *ctx,
                     const uint8_t key[16] );

/**
 * \brief           This function starts a GHASH computation and prepares to
 *                  authenticate the input data.
 * \param[in] ctx   The GHASH context.
 * \param[in] iv    The 128-bit initialization vector.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_start( te_ghash_ctx_t *ctx,
                    uint8_t *iv );

/**
 * \brief           This function feeds an input buffer into an ongoing GHASH
 *                  computation.
 *
 *                  It is called between te_ghash_start() or te_ghash_reset(),
 *                  and te_ghash_finish(). Can be called repeatedly.
 *
 * \param[in] ctx   The GHASH context.
 * \param[in] len   The length of the input data.
 * \param[in] in    The buffer holding the input data.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_update( te_ghash_ctx_t *ctx,
                     size_t len,
                     const uint8_t *in );

/**
 * \brief           This function feeds a list of input buffers into an ongoing
 *                  GHASH computation.
 *
 *                  It is called between te_ghash_start() or te_ghash_reset(),
 *                  and te_ghash_finish(). Can be called repeatedly.
 *
 * \param[in] ctx   The GHASH context.
 * \param[in] in    The list of buffers holding the input data.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_uplist( te_ghash_ctx_t *ctx,
                     te_memlist_t *in );

/**
 * \brief           This function finishes the GHASH computation and writes the
 *                  result to the mac buffer.
 *
 *                  The total length of the input data fed to the GHASH
 *                  operation before must be multiple of 16 bytes.
 *
 *                  It is called after te_ghash_update() or te_ghash_uplist().
 *                  It can be followed by te_ghash_start() or te_ghash_free().
 *
 * \param[in] ctx    The GHASH context.
 * \param[out] mac   The buffer holding the mac data.
 * \param[in] maclen The length of the mac data.
 * \return           \c TE_SUCCESS on success.
 * \return           \c <0 on failure.
 */
int te_ghash_finish( te_ghash_ctx_t *ctx,
                     uint8_t *mac,
                     uint32_t maclen );

/**
 * \brief           This function resets the GHASH computation and prepares the
 *                  computation of another message with the same key as the
 *                  previous GHASH operation.
 *
 *                  It is called after te_ghash_update() or te_ghash_uplist().
 *
 * \param[in] ctx   The GHASH context.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_reset( te_ghash_ctx_t *ctx );

/**
 * \brief           This function clones the state of a GHASH operation.
 *                  This function will free the \p dst context before clone if
 *                  it pointed to a valid GHASH context already.
 *
 * \param[in]  src  The source GHASH context.
 * \param[out] dst  The destination GHASH context.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_clone( const te_ghash_ctx_t *src,
                    te_ghash_ctx_t *dst );

/**
 * \brief           This function exports partial state of the calculation.
 *                  This function dumps the entire state of the specified con-
 *                  text into a provided block of data so it can be @import 'ed
 *                  back later on. This is useful in case you want to save
 *                  partial result of the calculation after processing certain
 *                  amount of data and reload this partial result multiple
 *                  times later on for multiple re-use.
 *
 * \param[in]  ctx  The GHASH context.
 * \param[out] out  Buffer filled with the state data on success.
 * \param[inout] olen Size of \p out buffer on input.
 *                    Length of data filled in the \p out buffer on success.
 *                    Required \p out buffer length on TE_ERROR_SHORT_BUFFER.
 * \return          \c TE_SUCCESS on success.
 *                  \c TE_ERROR_SHORT_BUFFER if *olen is less than required.
 * \return          \c <0 on failure.
 */
int te_ghash_export( te_ghash_ctx_t *ctx,
                     void *out,
                     uint32_t *olen );

/**
 * \brief           This function imports partial state of the calculation.
 *                  This function loads the entire state of the specified con-
 *                  text from a provided block of data so the calculation can
 *                  continue from this point onward.
 *
 * \param[in] ctx   The GHASH context.
 * \param[in] in    Buffer filled with the state data exported early.
 * \param[in] ilen  Size of the state data in the \p in buffer.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_ghash_import( te_ghash_ctx_t *ctx,
                     const void *in,
                     uint32_t ilen );

#endif /* !__ASSEMBLY__ */

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTENGINE_GHASH_H__ */
