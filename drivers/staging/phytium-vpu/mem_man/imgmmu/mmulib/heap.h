/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef IMGMMU_HEAP_H
#define IMGMMU_HEAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <img_types.h>

/**
 * @defgroup IMGMMU_heap MMU Heap Interface
 * @brief The API for the device virtual address Heap - must be implemented
 * (see tal_heap.c for an example implementation)
 * @ingroup IMGMMU_lib
 * @{
 */
/*-----------------------------------------------------------------------------
 * Following elements are in the IMGMMU_heap documentation module
 *---------------------------------------------------------------------------
 */

/** @brief An allocation on a heap. */
struct MMUHeapAlloc {
    /** @brief Start of the allocation */
	uintptr_t uiVirtualAddress;
    /** @brief Size in bytes */
	size_t uiAllocSize;
};

/**
 * @brief A virtual address heap - not directly related to HW MMU directory
 * entry
 */
struct MMUHeap {
    /** @brief Start of device virtual address */
	uintptr_t uiVirtAddrStart;
    /** @brief Allocation atom in bytes */
	size_t uiAllocAtom;
    /** @brief Total size of the heap in bytes */
	size_t uiSize;
};

/**
 * @name Device virtual address allocation (heap management)
 * @{
 */

/**
 * @brief Create a Heap
 *
 * @param uiVirtAddrStart start of the heap - must be a multiple of uiAllocAtom
 * @param uiAllocAtom the minimum possible allocation on the heap in bytes
 * - usually related to the system page size
 * @param uiSize total size of the heap in bytes
 * @param pResult must be non-NULL - used to give detail about error
 *
 * @return pointer to the new Heap object and pResult is IMG_SUCCESS
 * @return NULL and the value of pResult can be:
 * @li IMG_ERROR_MALLOC_FAILED if internal allocation failed
 */
struct MMUHeap *IMGMMU_HeapCreate(uintptr_t uiVirtAddrStart,
		size_t uiAllocAtom, size_t uiSize, s32 *pResult);

/**
 * @brief Allocate from a heap
 *
 * @warning Heap do not relate to each other, therefore one must insure that
 * they should not overlap if they should not.
 *
 * @param pHeap must not be NULL
 * @param uiSize allocation size in bytes
 * @param pResult must be non-NULL - used to give details about error
 *
 * @return pointer to the new HeapAlloc object and pResult is IMG_SUCCESS
 * @return NULL and the value of pResult can be:
 * @li IMG_ERROR_INVALID_PARAMETERS if the give size is not a multiple of
 * pHeap->uiAllocAtom
 * @li IMG_ERROR_MALLOC_FAILED if the internal structure allocation failed
 * @li IMG_ERROR_NOT_SUPPORTED if the internal device memory allocator did not
 * find a suitable virtual address
 */
struct MMUHeapAlloc *IMGMMU_HeapAllocate(struct MMUHeap *pHeap,
		size_t uiSize, s32 *pResult);

/**
 * @brief Liberate an allocation
 *
 * @return IMG_SUCCESS
 */
s32 IMGMMU_HeapFree(struct MMUHeapAlloc *pAlloc);

/**
 * @brief Destroy a heap object
 * @return IMG_SUCCESS
 * @return IMG_ERROR_NOT_SUPPORTED if the given Heap still has attached
 * allocation
 */
s32 IMGMMU_HeapDestroy(struct MMUHeap *pHeap);

/**
 * @}
 */
/*-----------------------------------------------------------------------------
 * End of the public functions
 *---------------------------------------------------------------------------
 */

/**
 * @}
 */
/*-----------------------------------------------------------------------------
 * End of the IMGMMU_heap documentation module
 *---------------------------------------------------------------------------
 */

#ifdef __cplusplus
}
#endif

#endif // IMGMMU_HEAP_H
