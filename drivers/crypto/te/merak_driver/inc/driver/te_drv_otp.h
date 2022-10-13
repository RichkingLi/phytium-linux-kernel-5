//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#ifndef __TRUSTENGINE_DRV_OTP_H__
#define __TRUSTENGINE_DRV_OTP_H__

#include "te_drv.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __ASSEMBLY__


/**
 * OTP LAYOUT
 */

enum {
    TE_OTP_MODEL_ID_OFFSET = 0x00U,
    TE_OTP_MODEL_KEY_OFFSET = 0x04U,
    TE_OTP_DEVICE_ID_OFFSET = 0x14U,
    TE_OTP_DEVICE_RK_OFFSET = 0x18U,
    TE_OTP_SEC_BOOT_HASH_OFFSET = 0x28U,
    TE_OTP_LCS_OFFSET = 0x48U,
    TE_OTP_LOCK_CTRL_OFFSET = 0x4CU,
    TE_OTP_USER_NON_SEC_REGION_OFFSET = 0x50U,
};

enum {
    TE_OTP_MODEL_ID_SIZE = 0x04U,
    TE_OTP_MODEL_KEY_SIZE = 0x10U,
    TE_OTP_DEVICE_ID_SIZE = 0x04U,
    TE_OTP_DEVICE_RK_SIZE = 0x10U,
    TE_OTP_SEC_BOOT_HASH_SIZE = 0x20U,
    TE_OTP_LCS_SIZE = 0x04U,
    TE_OTP_LOCK_CTRL_SIZE = 0x04U,
};

struct te_hwa_otp;
struct te_hwa_otpctl;

/**
 * Ememory PUF specific operation structure
 */
typedef struct emem_puf_ops {
    char name[TE_MAX_DRV_NAME];     /**< vendor name */
    int (*ready)(te_ctx_handle h);
    int (*enroll)(te_ctx_handle h);
    int (*quality_check)(te_ctx_handle h);
    int (*init_margin_read)(te_ctx_handle h, size_t off,
                            uint8_t *buf, size_t len);
    int (*pgm_margin_read)(te_ctx_handle h, size_t off,
                           uint8_t *buf, size_t len);

} emem_puf_ops_t;


typedef struct te_otp_conf {
    bool otp_exist;
    uint16_t otp_tst_sz;         /**< test region size in byte */
    uint8_t otp_s_sz;            /**< sec region size in byte */
    uint8_t otp_ns_sz;           /**< ns region size in byte */
}te_otp_conf_t;
/**
 * OTP driver magic number
 */
#define OTP_DRV_MAGIC   0x4470744fU /**< "OtpD" */

/**
 * Trust engine OTP driver structure
 */
typedef struct te_otp_drv {
    te_crypt_drv_t base;            /**< base driver */
    uint32_t magic;                 /**< OTP driver magic */
    te_ctx_handle hctx;             /**< OTP context handler */

    /**
     * CTL specific ops
     */
    int (*write)(te_ctx_handle h, size_t off,
                 const uint8_t *buf, size_t len);
    int (*get_vops)(te_ctx_handle h, void **pvops);
} te_otp_drv_t;

/**
 * \brief           This function initializes the supplied OTP driver instance
 *                  \p drv by binding it to the given OTP \p otp, and OTP CTL
 *                  \p ctl if exists.
 *
 *                  Note the \p ctl is required by the OTP driver of the host0
 *                  only. Shall set it to NULL elsewhere. This function could
 *                  have sanity check logic around \p ctl.
 *
 *                  A OTP context instance will be created with its crypto
 *                  context linked to \p drv->ctx on success.
 *
 * \param[in] drv   The OTP driver instance.
 * \param[in] rnp   The OTP HWA instance.
 * \param[in] ctl   The OTP CTL HWA instance.
 * \param[in] name  The OTP driver name. Or NULL to ignore.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_otp_drv_init( te_otp_drv_t *drv,
                     const struct te_hwa_otp *otp,
                     const struct te_hwa_otpctl *ctl,
                     const char* name );

/**
 * \brief           This function withdraws the supplied OTP driver instance
 *                  \p drv.
 * \param[in] drv   The OTP driver instance.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_otp_drv_exit( te_otp_drv_t *drv );

/**
 * \brief           This function reads the specified length \p len of otp
 *                  data starting from offset \p off and writes it to \p buf.
 * \param[in] drv   The OTP driver instance.
 * \param[in] off   The offset into the otp table.
 * \param[out] buf  The buffer holding the desired otp data.
 * \param[in] len   The length of desired otp data.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_otp_read( te_otp_drv_t *drv,
                 size_t off,
                 uint8_t *buf,
                 size_t len );
/**
 * \brief           This function gets configurations of OTP
 * \param[in] drv   The OTP driver instance.
 * \param[out] conf The obj holding OTP config.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
int te_otp_get_conf(te_otp_drv_t *drv,
                    te_otp_conf_t *conf);

/**
 * \brief           This function writes the specified length \p len of data
 *                  into otp starting from an offset of \p off.
 * \param[in] drv   The OTP driver instance.
 * \param[in] off   The offset into the otp table.
 * \param[in] buf   The buffer holding the otp data.
 * \param[in] len   The length of otp data.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
static inline int te_otp_write( te_otp_drv_t *drv,
                                size_t off,
                                const uint8_t *buf,
                                size_t len )
{
    if (NULL == drv)
        return TE_ERROR_BAD_PARAMS;

    if (drv->write != NULL) {
        return drv->write(drv->hctx, off, buf, len);
    } else {
        (void)off;
        (void)buf;
        (void)len;
        return TE_ERROR_NOT_SUPPORTED;
    }
}

/**
 * \brief           This function gets the vendor specific operation if exists
 *                  and writes its handler to \p vops.
 * \param[in] drv   The OTP driver instance.
 * \param[out] vops The pointer loading the vops handler on success.
 * \return          \c TE_SUCCESS on success.
 * \return          \c <0 on failure.
 */
static inline int te_otp_get_vops( te_otp_drv_t *drv,
                                   void **vops )
{
    if (NULL == drv)
        return TE_ERROR_BAD_PARAMS;

    if (drv->get_vops != NULL) {
        return drv->get_vops(drv->hctx, vops);
    } else {
        (void)vops;
        return TE_ERROR_NOT_SUPPORTED;
    }
}

#endif /* !__ASSEMBLY__ */

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTENGINE_DRV_OTP_H__ */
