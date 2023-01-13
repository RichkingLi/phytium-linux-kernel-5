//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#include <linux/sysfs.h>
#include <linux/device.h>
#include "lca_te_driver.h"
//#include "driver/te_drv.h"
#include "driver/te_drv_otp.h"

#define MAX(a,b,c) ((a)>(b)?((a)>(c)?(a):(c)):((b)>(c)?(b):(c)))
#define MAX_BASIC_OTP_PARTTI_SIZE (32)
#define BASIC_OTP_PARTTI_NUM (7)
#define EXT_OTP_PARTTI_NUM (3)

struct otp_info {
	char *name;
	size_t len;
};
static const struct otp_info basic_otp[BASIC_OTP_PARTTI_NUM] = {
/* basic otp info, the len is constant */
{
	.name = "model_id",
	.len = 4,
},
{
	.name = "model_key",
	.len = 16,
},
{
	.name = "device_id",
	.len = 4,
},
{
	.name = "dev_root_key",
	.len = 16,
},
{
	.name = "secboot_pubkey_hash",
	.len = 32,
},
{
	.name = "life_cycle",
	.len = 4,
},
{
	.name = "lock_control",
	.len = 4,
},
};
static struct otp_info ext_otp[EXT_OTP_PARTTI_NUM] = {
/* ext otp info, the len will be updated */
{
	.name = "usr_non_sec_region",
	.len = 0,
},
{
	.name = "usr_sec_region",
	.len = 0,
},
{
	.name = "test_region",
	.len = 0,
},

};


static ssize_t otp_show(struct device *,
		struct device_attribute *, char *);

static struct device_attribute dev_attr_otp = __ATTR(otp, 0444,
		otp_show, NULL);


static ssize_t otp_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int rc=0;
	char *p = buf;
	struct te_drvdata *drvdata = (struct te_drvdata *)dev->driver_data;
	te_crypt_drv_t *te_drv;
	struct te_otp_conf otp_conf;
	int bytes_remain = PAGE_SIZE;
	int bytes = 0;
	int i,j;
	unsigned char *q;
	size_t q_size,offset;
	size_t otp_ext_size;

	/*Question: do we need to add lock here? if it does, which one?*/
	te_drv = te_drv_get(drvdata->h,TE_DRV_TYPE_OTP);
	if(te_drv == NULL) {
		return 0;
	}

	rc = te_otp_get_conf((te_otp_drv_t *)te_drv, &otp_conf);
	if(rc != 0 || !otp_conf.otp_exist) {
		goto fail0;
	}
	otp_ext_size = MAX(otp_conf.otp_ns_sz,
					otp_conf.otp_s_sz, otp_conf.otp_tst_sz);
	q_size = ((MAX_BASIC_OTP_PARTTI_SIZE > otp_ext_size)?
		MAX_BASIC_OTP_PARTTI_SIZE : otp_ext_size);

	q = kmalloc(q_size,GFP_KERNEL);
	if(q == NULL) {
		goto fail0;
	}
	/* get basic otp info */
	bytes = 0;
	offset = 0;
	for(i=0;i<BASIC_OTP_PARTTI_NUM;i++) {
		bytes += snprintf(p+bytes, bytes_remain-bytes, "%s:",
			basic_otp[i].name);
		rc = te_otp_read((te_otp_drv_t *)te_drv, offset, q,
			basic_otp[i].len);

		offset += basic_otp[i].len;
		if(rc == 0) {
			for(j=0;j<basic_otp[i].len;j++) {
				if(j == basic_otp[i].len - 1)
					bytes += snprintf(p+bytes, bytes_remain-bytes,
					"%02x\r\n", q[j]);
				else
					bytes+=snprintf(p+bytes, bytes_remain-bytes,
					"%02x", q[j]);
			}
		} else {
			bytes += snprintf(p+bytes, bytes_remain-bytes, "%s\r\n",
				"N/A");
		}
	}

	/* get ext otp info */
	ext_otp[0].len = otp_conf.otp_ns_sz;
	ext_otp[1].len = otp_conf.otp_s_sz;
	ext_otp[2].len = otp_conf.otp_tst_sz;
	for(i=0;i<EXT_OTP_PARTTI_NUM;i++) {
		bytes += snprintf(p+bytes, bytes_remain-bytes, "%s:",
			ext_otp[i].name);
		rc = te_otp_read((te_otp_drv_t *)te_drv, offset, q,
			ext_otp[i].len);

		offset += ext_otp[i].len;
		if(rc == 0 && ext_otp[i].len > 0) {
			for(j=0;j<ext_otp[i].len;j++) {
				if(j == ext_otp[i].len - 1)
					bytes += snprintf(p+bytes, bytes_remain-bytes,
					"%02x\r\n", q[j]);
				else
					bytes+=snprintf(p+bytes, bytes_remain-bytes,
					"%02x", q[j]);
			}
		} else {
			bytes += snprintf(p+bytes, bytes_remain-bytes, "%s\r\n",
				"N/A");
		}
	}

	kfree(q);
fail0:
	te_drv_put(drvdata->h,TE_DRV_TYPE_OTP);
	return bytes;
}

static struct attribute *lca_te_sysfs_entries[] = {
	&dev_attr_otp.attr,
	NULL,
};

static struct attribute_group otp_attribute_group = {
	.name = "otp",		/* put in device directory */
	.attrs = lca_te_sysfs_entries,
};

static struct device *__dev = NULL;
int lca_te_otp_alloc(struct te_drvdata *drvdata)
{
	int rc = 0;

	__dev = drvdata_to_dev(drvdata);

	if (sysfs_create_group(&__dev->kobj, &otp_attribute_group)) {
		dev_err(__dev, "could not create sysfs device attributes\n");
		rc = -1;
	}

	return rc;
}

int lca_te_otp_free(struct te_drvdata *drvdata)
{
	int rc = 0;
	struct device *dev = drvdata_to_dev(drvdata);

	sysfs_remove_group(&dev->kobj, &otp_attribute_group);
	__dev = NULL;
	return rc;
}

int lca_te_otp_read(size_t offset, uint8_t *buf, size_t len )
{
	int rc=0;
	struct te_drvdata *drvdata;
	te_crypt_drv_t *te_drv;

	if(__dev == NULL) {
		return -ENXIO;
	}
	drvdata = (struct te_drvdata *)__dev->driver_data;
	te_drv = te_drv_get(drvdata->h,TE_DRV_TYPE_OTP);
	if(te_drv == NULL) {
		return -ENXIO;
	}

	rc = te_otp_read((te_otp_drv_t *)te_drv, offset, buf, len);

	te_drv_put(drvdata->h,TE_DRV_TYPE_OTP);
	return rc;
}

EXPORT_SYMBOL_GPL(lca_te_otp_read);


