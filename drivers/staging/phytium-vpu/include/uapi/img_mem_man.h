/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef IMG_MEM_MAN_UAPI_H
#define IMG_MEM_MAN_UAPI_H

enum img_mem_attr {
	IMG_MEM_ATTR_CACHED        = 0x00000001,
	IMG_MEM_ATTR_UNCACHED      = 0x00000002,
	IMG_MEM_ATTR_WRITECOMBINE  = 0x00000004,
	IMG_MEM_ATTR_SECURE        = 0x00000010,
};

/* buffer ids (per memory context) */
#define IMG_MEM_MAN_MIN_BUFFER 1
#define IMG_MEM_MAN_MAX_BUFFER 16384

#endif /* IMG_MEM_MAN_UAPI_H */
