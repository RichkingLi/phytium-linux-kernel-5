/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef VXD_PLAT_H
#define VXD_PLAT_H

int vxd_plat_init(void);
int vxd_plat_deinit(void);

extern const unsigned long vxd_plat_poll_udelay;

#endif /* VXD_PLAT_H */
