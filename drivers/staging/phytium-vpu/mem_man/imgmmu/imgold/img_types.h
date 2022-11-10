/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __IMG_TYPES__
#define __IMG_TYPES__

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif
#include "img_systypes.h" // system specific type definitions

#ifdef __GNUC__
#define IS_NOT_USED __attribute__((unused))
#else
#define IS_NOT_USED
#endif

/*
 * Typedefs of void are synonymous with the void keyword in C,
 * but not in C++. In order to support the use of IMG_VOID
 * in place of the void keyword to specify that a function takes no
 * arguments, it must be a macro rather than a typedef.
 */
#define IMG_VOID void
#define IMG_NULL NULL
#define	IMG_FALSE	0
#define	IMG_TRUE	1

#endif /* __IMG_TYPES__ */
