/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __IMG_SYSDEFS__
#define __IMG_SYSDEFS__

#include <linux/stddef.h>
#include <linux/string.h> // strcpy, ... and memcpy, ...
#include <linux/kernel.h>
#include <linux/slab.h> // kmalloc, kcalloc, ...
#include <linux/vmalloc.h>
#include <linux/interrupt.h> // to check if in interrupt context when doing kmalloc

#ifdef __cplusplus
extern "C" {
#endif

/*
 * language abstraction
 */
#define IMG_CONST const
#define IMG_INLINE inline

// not very nice
#define IMG_LITTLE_ENDIAN	(1234)
#define IMG_BIG_ENDIAN		(4321)
/* Win32 is little endian */
#define	IMG_BYTE_ORDER		IMG_LITTLE_ENDIAN

/**
 * @brief 64bit value prefix - e.g. printf("long %" IMG_I64PR "d")
 */
#ifdef __GNUC__
#  ifdef __LP64__
#    define IMG_I64PR "l"
#  else
#    define IMG_I64PR "ll"
#  endif
#else
#  if defined(__x86_64__) || defined(__ppc64__) || defined(__aarch64__)
#    define IMG_I64PR "l"
#  else
#    define IMG_I64PR "ll"
#  endif
#endif
#define IMG_INT64PRFX IMG_I64PR /* backwards compatibility */
#define IMG_SIZEPR "z"
#define IMG_SIZEPRFX IMG_SIZEPR /* backwards compatibility */
#define IMG_PTRDPR "t"
#define IMG_PTRDIFFPRFX IMG_PTRDPR /* backwards compatibility */

/*
 * memory operation
 */

  /**
   * @brief kmalloc flags used when calling kmalloc in IMG_MALLOC
   *
   * The two most common flags are:
   * @li GFP_ATOMIC is high priority and cannot sleep (use in interrupt handlers and bottom halves)
   * when using a spin lock. As the kernel cannot put the process to sleep it cannot swap pages
   * etc to maybe make memory available therefore it has more chances to fail.
   * Therefore it should be used only in the contexts where memory allocation must
   * be done very fast in a small amount.
   * @li GFP_KERNEL is a normal priority allocation that can sleep,
   * therefore the kernel can liberate memory if possible (unused pages etc).
   *
   * Therefore GFP_ATOMIC usage should be avoided in most of the cases.
   * It is sensible however to AVOID allocation in the cases GFP_ATOMIC should be used.
   *
   * The allocation checks if the requiered memory fits in a page.
   * If it does not then malloc is attempted but warning is printed).
   */
#define IMG_KMALLOC_FLAG GFP_KERNEL
#define	IMG_MEMCPY(dest, src, size)	memcpy(dest, src, size)
#define IMG_MEMCMP(A, B, size)		memcmp(A, B, size)
#define IMG_MEMMOVE(dest, src, size)	memmove(dest, src, size)

#if defined(__aarch64__)
/* Short term work-around:
 * ARM64 kernel memset performs a 64bit unaligned operation.
 * This does not work on uncached memory.
 */
#define IMG_MEMSET(p, v, n)\
	({long x = -(long)(p)&7; if (x) memset(p, v, x); memset(((void *)p) + x, v, n - x); p; })
#else
#define	IMG_MEMSET(ptr, val, size)	memset(ptr, val, size)
#endif

/** @brief C89 says: space is unitialized */

/// @return 0 if correct, more than 0 otherwise
static inline int img_verifalloc(size_t size, const char *fct,
		const char *file, uint32_t line, int verif)
{
	int ret = 0;

	if (irqs_disabled()) {
		pr_info("WARNING: %s with irq disabled! %s:%u", fct, file, line);
		if (IMG_KMALLOC_FLAG != GFP_ATOMIC) {
			dump_stack();
			ret++; // so it only prints the warning and does not allocate
		}
	}
	if (verif && size > 2 * PAGE_SIZE)
		pr_info("WARNING: %s (%zu) > 2 pages. Maybe use vmalloc. %s:%u",
				fct, size, file, line);

	return ret;
}

static inline void *img_sys_malloc(size_t size, const char *fct, uint32_t line)
{
	void *ptr = NULL;

	if (size == 0)
		pr_err("%s:%d error: kmalloc(0)\n", fct, line);
	else if (!img_verifalloc(size, "kmalloc", fct, line, 1))
		ptr = kmalloc(size, IMG_KMALLOC_FLAG);

	return ptr;
}
#define IMG_SYSMALLOC(size) img_sys_malloc(size, __FILE__, __LINE__)


/** @brief C89 says: space is initialized to zero bytes */
static inline void *img_sys_calloc(size_t nelem, size_t elem_size, const char *fct, uint32_t line)
{
	void *ptr = NULL;

	if (!img_verifalloc(nelem*elem_size, "kcalloc", fct, line, 1))
		ptr = kcalloc(nelem, elem_size, IMG_KMALLOC_FLAG);

	return ptr;
}
#define IMG_SYSCALLOC(nelem, elem_size) img_sys_calloc(nelem, elem_size, __FILE__, __LINE__)

/** @brief C89 says: if the size is larger the new space is uninitialized. */
static inline void *img_sys_realloc(void *ptr, size_t size, const char *fct, uint32_t line)
{
	void *reptr = NULL;

	if (!img_verifalloc(size, "krealloc", fct, line, 1))
		reptr = krealloc(ptr, size, IMG_KMALLOC_FLAG);

	return reptr;
}
#define IMG_SYSREALLOC(ptr, size) img_sys_realloc(ptr, size, __FILE__, __LINE__)

/*
 * @brief In the kernel allocation that are more than a few
 * page (1 or 2) should use vmalloc because it allows fragmented memory
 */
static inline void *img_sys_vmalloc(size_t size, const char *fct, uint32_t line)
{
	void *ptr = NULL;

	if (size == 0)
		pr_err("%s:%d error: kmalloc(0)\n", fct, line);
	else if (!img_verifalloc(size, "vmalloc", fct, line, 0))
		ptr = vmalloc(size);

	return ptr;
}
#define IMG_SYSBIGALLOC(size) img_sys_vmalloc(size, __FILE__, __LINE__)

#define IMG_SYSFREE(ptr)         kfree(ptr)
#define IMG_SYSBIGFREE(ptr)      vfree(ptr)
/** @brief With GCC this aligns the memory */
#define IMG_ALIGN(bytes)       __aligned(bytes)

/*
 * string operation
 */

static inline char *img_sys_strdup(char *ptr, const char *fct, uint32_t line)
{
	char *str = NULL;

	if (!img_verifalloc(strlen(ptr), "kstrdup", fct, line, 1))
		str = kstrdup(ptr, IMG_KMALLOC_FLAG);
	return str;
}
#define IMG_SYS_STRDUP(ptr) img_sys_strdup(ptr, __FILE__, __LINE__)

#define IMG_STRCMP(A, B)		strcmp(A, B)
#define IMG_STRCPY(dest, src)		strcpy(dest, src)
#define IMG_STRNCPY(dest, src, size)	strncpy(dest, src, size)
#define IMG_STRLEN(ptr) strlen(ptr)

/*
 * file operation
 */

/*
 * If IMG_NO_FSEEK64 is defined then the FSEEK64 is not set
 * This allows the projects to choose if they want FSEEK64 support
 *
 * Similar operation for FTELL64
 */

// force to NO
#define IMG_NO_FTELL64
// force to NO
#define IMG_NO_FSEEK64


/*
 * assert behaviour
 *                               NDEBUG
 *                      0                 1
 * EXIT_ON_ASSERT  0   test||print        void
 *                 1   assert()           assert() // ignored  no print, no exit
 */

/* C89 says: if NDEBUG is defined at the time <assert.h>
 * is included the assert macro is ignored
 */
#ifdef EXIT_ON_ASSERT

#define IMG_ASSERT(expected) ({WARN_ON(!(expected)); 0; })

#else // NO_EXIT_ON_ASSERT is defined

// IMG_ASSERT is enabled in release: customer logs are not useful unless asserts are visible
// #define IMG_ASSERT(expected) ({0;})
#define IMG_ASSERT(expected) (void)((expected) ||\
		(pr_err("Assertion failed: %s, file %s, line %d\n",\
		#expected, __FILE__, __LINE__), dump_stack(), 0))

#endif // NO_EXIT_ON_ASSERT

/*
 * Do not #define container_of because the linux kernel defines it
 */

#ifdef __cplusplus
}
#endif

#endif // __IMG_SYSDEFS__
