/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef VXD_PVDEC_H
#define VXD_PVDEC_H

#define PVDEC_COMMS_RAM_OFFSET      0x00002000
#define PVDEC_COMMS_RAM_SIZE        0x00001000
#define PVDEC_ENTROPY_OFFSET        0x00003000
#define PVDEC_ENTROPY_SIZE          0x1FF
#define PVDEC_VEC_BE_OFFSET         0x00005000
#define PVDEC_VEC_BE_SIZE           0x3FF
#define PVDEC_VEC_BE_CODEC_OFFSET   0x00005400
#define MSVDX_VEC_OFFSET            0x00006000
#define MSVDX_VEC_SIZE              0x7FF
#define MSVDX_CMD_OFFSET            0x00007000

/* Defines virtual memory area separation space size.
 * It's used to avoid memory overwriting in case of neighbouring areas.
 */
#define PVDEC_GUARD_BAND            0x00001000ul

/* Virtual memory address ranges for hardware
 * related buffers allocated in the kernel driver.
 */
#define PVDEC_BUF_FW_START          0x00042000ul
#define PVDEC_BUF_RENDEC_START      0x00400000ul
#define PVDEC_BUF_RENDEC_SIZE       (0x02000000ul - PVDEC_GUARD_BAND)
#define PVDEC_BUF_END  (PVDEC_BUF_RENDEC_START + \
			PVDEC_BUF_RENDEC_SIZE + \
			PVDEC_GUARD_BAND)

/* Use of tiled heaps. */
/* Define to 1 if 512-byte stride tiled heap is to be used.
 * Otherwise define to 0.
 */
#define PVDEC_USE_HEAP_TILE512  0

/* Virtual memory heap address ranges for tiled
 * and non-tiled buffers. Addresses within each
 * range should be assigned to the appropriate
 * buffers by the UM driver and mapped into the
 * device using the corresponding KM driver ioctl.
 */
#define PVDEC_HEAP_UNTILED_START	(PVDEC_BUF_END)
#define PVDEC_HEAP_UNTILED_SIZE		(0x3DC00000ul)
#define PVDEC_HEAP_TILE512_START	(PVDEC_HEAP_UNTILED_START + \
					PVDEC_HEAP_UNTILED_SIZE)
#define PVDEC_HEAP_TILE512_SIZE		(0x10000000ul * PVDEC_USE_HEAP_TILE512)
#define PVDEC_HEAP_TILE1024_START	(PVDEC_HEAP_TILE512_START + \
					PVDEC_HEAP_TILE512_SIZE)
#define PVDEC_HEAP_TILE1024_SIZE	(0x20000000ul)
#define PVDEC_HEAP_TILE2048_START	(PVDEC_HEAP_TILE1024_START + \
					PVDEC_HEAP_TILE1024_SIZE)
#define PVDEC_HEAP_TILE2048_SIZE	(0x30000000ul)
#define PVDEC_HEAP_TILE4096_START	(PVDEC_HEAP_TILE2048_START + \
					PVDEC_HEAP_TILE2048_SIZE)
#define PVDEC_HEAP_TILE4096_SIZE	(0x40000000ul)
#define PVDEC_HEAP_BITSTREAM_START	(PVDEC_HEAP_TILE4096_START + \
					PVDEC_HEAP_TILE4096_SIZE)
//jiangy
//#define PVDEC_HEAP_BITSTREAM_SIZE   (0x02000000ul)
#define PVDEC_HEAP_BITSTREAM_SIZE	(0x20000000ul)
#define PVDEC_HEAP_STREAM_START		(PVDEC_HEAP_BITSTREAM_START + \
					PVDEC_HEAP_BITSTREAM_SIZE)
#define PVDEC_HEAP_STREAM_SIZE		(0x100000000 - PVDEC_HEAP_STREAM_START)
#if ((PVDEC_HEAP_STREAM_START) >= 0x100000000)
    #error "PVDEC MMU heap definitions exceed 4GB!"
#endif

#endif /* VXD_PVDEC_H */
