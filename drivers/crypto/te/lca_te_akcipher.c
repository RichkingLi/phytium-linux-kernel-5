//SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 ARM Technology (China) Co., Ltd.
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/internal/rsa.h>
#include <crypto/internal/akcipher.h>
#include <crypto/akcipher.h>
#include <crypto/scatterwalk.h>

#include "te_bn.h"
#include "te_rsa.h"
#include "lca_te_driver.h"


#define TE_LCA_CHECK_RET_GO                                                    \
    do {                                                                       \
        if ((TE_SUCCESS) != (rc)) {                                            \
            goto finish;                                                       \
        }                                                                      \
    } while (0)


/* may need change according to Merak RTL config*/
#define	TE_RSA_MAX_SIZE	(4 * 1024 / 8)

struct te_akcipher_handle {
	struct list_head akcipher_list;
};

struct lca_te_rsa_key_t {
	te_bn_t *N;
	te_bn_t *E;
	te_bn_t *D;
	te_bn_t *P;
	te_bn_t *Q;
	te_bn_t *DP;
	te_bn_t *DQ;
	te_bn_t *QP;
};

struct te_akcipher_ctx {
	struct te_drvdata *drvdata;
	unsigned int reqsize;
	union {
		struct lca_te_rsa_key_t rsa;
	}u;
};

struct te_akcipher_alg {
	struct list_head entry;
	unsigned int reqsize;
	struct te_drvdata *drvdata;
	struct akcipher_alg akcipher_alg;
};

struct te_akcipher_template {
	char name[CRYPTO_MAX_ALG_NAME];
	char driver_name[CRYPTO_MAX_ALG_NAME];
	struct akcipher_alg akcipher;
	unsigned int reqsize;
	struct te_drvdata *drvdata;
};

struct te_rsa_req_ctx {
	int buflen;
	u8 * buf;
	bool enc;
	te_rsa_request_t rsa;
};

static int te_rsa_init_key_bufs(struct te_akcipher_ctx *ctx)
{
	int rc=0;
	rc = te_bn_alloc(ctx->drvdata->h, 0, &ctx->u.rsa.N);
	TE_LCA_CHECK_RET_GO;
	rc = te_bn_alloc(ctx->drvdata->h, 0, &ctx->u.rsa.E);
	TE_LCA_CHECK_RET_GO;
	rc = te_bn_alloc(ctx->drvdata->h, 0, &ctx->u.rsa.P);
	TE_LCA_CHECK_RET_GO;
	rc = te_bn_alloc(ctx->drvdata->h, 0, &ctx->u.rsa.Q);
	TE_LCA_CHECK_RET_GO;
	rc = te_bn_alloc(ctx->drvdata->h, 0, &ctx->u.rsa.D);
	TE_LCA_CHECK_RET_GO;

	return 0;

finish:
	te_bn_free(ctx->u.rsa.N);
	te_bn_free(ctx->u.rsa.E);
	te_bn_free(ctx->u.rsa.P);
	te_bn_free(ctx->u.rsa.Q);
	te_bn_free(ctx->u.rsa.D);
	return rc;
}

static void te_rsa_free_key_bufs(struct te_akcipher_ctx *ctx)
{
	/* Clean up old key data */
	te_bn_free(ctx->u.rsa.N);
	te_bn_free(ctx->u.rsa.E);
	te_bn_free(ctx->u.rsa.P);
	te_bn_free(ctx->u.rsa.Q);
	te_bn_free(ctx->u.rsa.D);
}

static int te_rsa_setkey(struct crypto_akcipher *tfm, const void *key,
			  unsigned int keylen, bool private)
{
	struct te_akcipher_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct rsa_key raw_key;
	int rc;

	te_rsa_free_key_bufs(ctx);
	memset(&raw_key, 0, sizeof(raw_key));
	te_rsa_init_key_bufs(ctx);

	/* Code borrowed from crypto/rsa.c */
	if (private)
		rc = rsa_parse_priv_key(&raw_key, key, keylen);
	else
		rc = rsa_parse_pub_key(&raw_key, key, keylen);
	TE_LCA_CHECK_RET_GO;

	rc = te_bn_import(ctx->u.rsa.N, raw_key.n, raw_key.n_sz, 1);
	TE_LCA_CHECK_RET_GO;
	rc = te_bn_import(ctx->u.rsa.E, raw_key.e, raw_key.e_sz, 1);
	TE_LCA_CHECK_RET_GO;
	if(raw_key.d_sz) {
		rc = te_bn_import(ctx->u.rsa.D, raw_key.d, raw_key.d_sz, 1);
		TE_LCA_CHECK_RET_GO;
		rc = te_bn_import_s32(ctx->u.rsa.P, 0);
		TE_LCA_CHECK_RET_GO;
		rc = te_bn_import_s32(ctx->u.rsa.Q, 0);
		TE_LCA_CHECK_RET_GO;
		rc = te_rsa_complete_key(ctx->u.rsa.N, ctx->u.rsa.E, ctx->u.rsa.D,
						ctx->u.rsa.P,ctx->u.rsa.Q, NULL, NULL, NULL);
		TE_LCA_CHECK_RET_GO;
	}
	return 0;

finish:
	te_rsa_free_key_bufs(ctx);
	return rc;
}

static int te_rsa_setprivkey(struct crypto_akcipher *tfm, const void *key,
			      unsigned int keylen)
{
	return te_rsa_setkey(tfm, key, keylen, true);
}

static int te_rsa_setpubkey(struct crypto_akcipher *tfm, const void *key,
			     unsigned int keylen)
{
	return te_rsa_setkey(tfm, key, keylen, false);
}

static unsigned int te_rsa_maxsize(struct crypto_akcipher *tfm)
{
	return TE_RSA_MAX_SIZE;
}

static void te_akcipher_complete(struct te_async_request *te_req, int err)
{
	struct akcipher_request *req = (struct akcipher_request *)te_req->data;
	struct te_rsa_req_ctx *areq_ctx = akcipher_request_ctx(req);
	if(areq_ctx->enc) {
		req->dst_len = areq_ctx->rsa.public_args.size;
		if(areq_ctx->buf) {
			kfree_sensitive(areq_ctx->buf);
			areq_ctx->buf = NULL;
			areq_ctx->buflen = 0;
		}
	} else {
		req->dst_len = areq_ctx->rsa.private_args.size;
	}
	akcipher_request_complete(req, err);
}

static int te_rsa_encrypt(struct akcipher_request *req)
{
	int rc = 0;
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct te_akcipher_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct te_rsa_req_ctx *areq_ctx = akcipher_request_ctx(req);

	memset(areq_ctx, 0, sizeof(*areq_ctx));
	areq_ctx->rsa.public_args.N = ctx->u.rsa.N;
	areq_ctx->rsa.public_args.E= ctx->u.rsa.E;

	/* here we can't pass through the input buffer to driver,
	 * driver only support the input size equal to N size, so
	 * we need to malloc a buf for the input data
	 */
	areq_ctx->buflen = te_bn_bytelen(ctx->u.rsa.N);
	if(req->src_len > areq_ctx->buflen)
		return -EINVAL;
	areq_ctx->buf = kzalloc(areq_ctx->buflen, GFP_KERNEL);
	if(!areq_ctx->buf)
		return -ENOMEM;

	/* we treat the input buffer as the bignum data, so copy
	 * the data to the tail of the buffer
	 */
	sg_copy_to_buffer(req->src, sg_nents(req->src),
				areq_ctx->buf + areq_ctx->buflen - req->src_len, req->src_len);
	areq_ctx->rsa.public_args.input = areq_ctx->buf;
	areq_ctx->rsa.public_args.output = sg_virt(req->dst);
	areq_ctx->rsa.public_args.size = areq_ctx->buflen;
	areq_ctx->rsa.base.flags = req->base.flags;
	areq_ctx->rsa.base.data = req;
	areq_ctx->rsa.base.completion = te_akcipher_complete;
	areq_ctx->enc = true;
	rc = te_rsa_public_async(&areq_ctx->rsa);
	if(rc) {
		kfree_sensitive(areq_ctx->buf);
		areq_ctx->buf = NULL;
		areq_ctx->buflen = 0;
	}
	return ((rc == TE_SUCCESS) ? (-EINPROGRESS):rc);
}

static int te_rsa_decrypt(struct akcipher_request *req)
{
	int rc = 0;
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct te_akcipher_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct te_rsa_req_ctx *areq_ctx = akcipher_request_ctx(req);

	memset(areq_ctx, 0, sizeof(*areq_ctx));
	areq_ctx->rsa.private_args.N = ctx->u.rsa.N;
	areq_ctx->rsa.private_args.E= ctx->u.rsa.E;
	areq_ctx->rsa.private_args.D= ctx->u.rsa.D;
	areq_ctx->rsa.private_args.P= ctx->u.rsa.P;
	areq_ctx->rsa.private_args.Q= ctx->u.rsa.Q;
	areq_ctx->rsa.private_args.input = sg_virt(req->src);
	areq_ctx->rsa.private_args.output = sg_virt(req->dst);
	areq_ctx->rsa.private_args.size = req->src_len;
	areq_ctx->rsa.base.flags = req->base.flags;
	areq_ctx->rsa.base.data = req;
	areq_ctx->rsa.base.completion = te_akcipher_complete;
	areq_ctx->enc = false;

	rc = te_rsa_private_async(&areq_ctx->rsa);
	return ((rc == TE_SUCCESS) ? (-EINPROGRESS):rc);
}

static int te_rsa_init(struct crypto_akcipher *tfm)
{
	struct te_akcipher_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct akcipher_alg *alg = crypto_akcipher_alg(tfm);
	struct te_akcipher_alg *te_alg =
			container_of(alg, struct te_akcipher_alg, akcipher_alg);

	ctx->drvdata = te_alg->drvdata;

	akcipher_set_reqsize(tfm, sizeof(struct te_rsa_req_ctx));

	return te_rsa_init_key_bufs(ctx);
}

static void te_rsa_exit(struct crypto_akcipher *tfm)
{
	struct te_akcipher_ctx *ctx = crypto_tfm_ctx(&tfm->base);

	te_rsa_free_key_bufs(ctx);

}

static struct te_akcipher_template akcipher_algs[] = {
	{
		.name = "rsa",
		.driver_name = "rsa-te",
		.akcipher = {
			.encrypt = te_rsa_encrypt,
			.decrypt = te_rsa_decrypt,
			.sign = te_rsa_decrypt,
			.verify = te_rsa_encrypt,
			.set_pub_key = te_rsa_setpubkey,
			.set_priv_key = te_rsa_setprivkey,
			.max_size = te_rsa_maxsize,
			.init = te_rsa_init,
			.exit = te_rsa_exit,
		},
		.reqsize	= sizeof(struct te_rsa_req_ctx),
	},
};
static struct te_akcipher_alg *te_akcipher_create_alg(struct te_akcipher_template *tmpl)
{
	struct te_akcipher_alg *t_alg;
	struct akcipher_alg *alg;

	t_alg = kzalloc(sizeof(*t_alg), GFP_KERNEL);
	if (!t_alg) {
		return ERR_PTR(-ENOMEM);
	}
	alg = &tmpl->akcipher;

	snprintf(alg->base.cra_name, CRYPTO_MAX_ALG_NAME, "%s", tmpl->name);
	snprintf(alg->base.cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
		 tmpl->driver_name);
	alg->base.cra_module = THIS_MODULE;
	alg->base.cra_priority = TE_CRA_PRIO;

	alg->base.cra_ctxsize = sizeof(struct te_akcipher_ctx);
	alg->base.cra_flags = CRYPTO_ALG_ASYNC;

	t_alg->akcipher_alg = *alg;
	t_alg->reqsize = tmpl->reqsize;

	return t_alg;
}

int lca_te_akcipher_free(struct te_drvdata *drvdata)
{
	struct te_akcipher_alg *t_alg, *n;
	struct te_akcipher_handle *akcipher_handle =
		(struct te_akcipher_handle *)drvdata->akcipher_handle;

	if (akcipher_handle) {
		/* Remove registered algs */
		list_for_each_entry_safe(t_alg, n, &akcipher_handle->akcipher_list, entry) {
			crypto_unregister_akcipher(&t_alg->akcipher_alg);
			list_del(&t_alg->entry);
			kfree(t_alg);
		}
		kfree(akcipher_handle);
		drvdata->akcipher_handle = NULL;
	}

	return 0;
}

int lca_te_akcipher_alloc(struct te_drvdata *drvdata)
{
	struct te_akcipher_handle *akcipher_handle;
	struct te_akcipher_alg *t_alg;
	struct device *dev = drvdata_to_dev(drvdata);
	int rc = -ENOMEM;
	int alg;

	akcipher_handle = kmalloc(sizeof(*akcipher_handle), GFP_KERNEL);
	if (!akcipher_handle) {
		rc = -ENOMEM;
		goto fail0;
	}

	drvdata->akcipher_handle = akcipher_handle;


	INIT_LIST_HEAD(&akcipher_handle->akcipher_list);

	/* Linux crypto */
	for (alg = 0; alg < ARRAY_SIZE(akcipher_algs); alg++) {
		t_alg = te_akcipher_create_alg(&akcipher_algs[alg]);
		if (IS_ERR(t_alg)) {
			rc = PTR_ERR(t_alg);
			dev_err(dev, "%s alg allocation failed\n",
					akcipher_algs[alg].driver_name);
			goto fail1;
		}
		t_alg->drvdata = drvdata;
		rc = crypto_register_akcipher(&t_alg->akcipher_alg);
		if (unlikely(rc != 0)) {
			dev_err(dev, "%s alg registration failed\n",
					t_alg->akcipher_alg.base.cra_driver_name);
			goto fail2;
		} else {
			list_add_tail(&t_alg->entry, &akcipher_handle->akcipher_list);
			dev_err(dev, "Registered %s\n", t_alg->akcipher_alg.base.cra_driver_name);
		}
	}

	return 0;

fail2:
	kfree(t_alg);
fail1:
	lca_te_akcipher_free(drvdata);
fail0:
	return rc;
}


