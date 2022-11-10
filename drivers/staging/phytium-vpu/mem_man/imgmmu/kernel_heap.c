// SPDX-License-Identifier: GPL-2.0+

#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/genalloc.h>

#include <img_errors.h>
#include <img_defs.h>

#include "mmulib/heap.h"
#include "mmu_defs.h" // access to MMU info and error printing function

/**
 * @brief Internal heap object using genalloc
 */
struct GEN_Heap {
	struct gen_pool *pPool;
	/* we could use gen_get_size() but it goes through the list,
	 * it's easier to maintain a simple counter
	 */
	size_t uiNAlloc;
	struct MMUHeap sHeapInfo; // public element
};

/**
 * @brief The Heap allocation - contains an struct MMUHeapAlloc that is given to the caller
 */
struct GEN_HeapAlloc {
	struct GEN_Heap *pHeap;     ///< @brief Associated heap
	struct MMUHeapAlloc sVirtualMem; ///< @brief MMU lib allocation part (public element)
};

/**
 *  can be used for debugging
 *
 * example: gen_pool_for_each_chunk(pInternalAlloc->pHeap->pPool, &pool_crawler, pInternalAlloc);
 */
static void pool_crawler(struct gen_pool *pool,
		struct gen_pool_chunk *chunk, void *data) __maybe_unused;

static void pool_crawler(struct gen_pool *pool, struct gen_pool_chunk *chunk, void *data)
{
}

struct MMUHeap *IMGMMU_HeapCreate(uintptr_t uiVirtAddrStart, size_t uiAllocAtom,
		size_t uiSize, s32 *pResult)
{
	struct GEN_Heap *pNeo = NULL;
	int minAllocOrder = 0;
	size_t tmpSize = uiAllocAtom;
	uintptr_t uiStart = uiVirtAddrStart;

	IMG_ASSERT(pResult != NULL);
	IMG_ASSERT(uiSize > 0);

	if (uiSize%uiAllocAtom != 0 || (uiVirtAddrStart != 0 && uiVirtAddrStart%uiAllocAtom != 0)
	   ) {
		*pResult = IMG_ERROR_INVALID_PARAMETERS;
		return NULL;
	}

	pNeo = (struct GEN_Heap *)IMG_CALLOC(1, sizeof(struct GEN_Heap));
	if (pNeo == NULL) {
		*pResult = IMG_ERROR_MALLOC_FAILED;
		return NULL;
	}

	pNeo->uiNAlloc = 0;

	// compute log2 of the alloc atom
	while (tmpSize >>= 1)
		minAllocOrder++;

	/* ugly fix for trouble using gen_pool_alloc() when allocating a block
	 * gen_pool_alloc() returns 0 on error alought 0 can be a valid first virtual address
	 * therefore all addresses are offseted by the allocation atom to insure 0
	 * is the actual error code
	 */
	if (uiVirtAddrStart == 0)
		uiStart = uiVirtAddrStart+uiAllocAtom; // otherwise it is uiVritAddrStart

	tmpSize = uiStart + uiSize - 1;
	IMG_ASSERT(tmpSize > uiStart); // too big! it did an overflow

	MMU_LogDebug("create genalloc pool of order %u\n", minAllocOrder);
	pNeo->pPool = gen_pool_create(minAllocOrder, -1); // -1: not using real inode

	if (pNeo->pPool == NULL) {
		*pResult = IMG_ERROR_MALLOC_FAILED;
		MMU_LogError("Failure to create the genalloc pool\n");
		IMG_FREE(pNeo);
		return NULL;
	}

	if (gen_pool_add(pNeo->pPool, uiStart, uiSize, -1) != 0) {
		*pResult = IMG_ERROR_FATAL;
		gen_pool_destroy(pNeo->pPool);
		IMG_FREE(pNeo);
		return NULL;
	}

	//gen_pool_for_each_chunk(pNeo->pPool, &pool_crawler, pNeo->pPool);

	pNeo->sHeapInfo.uiVirtAddrStart = uiVirtAddrStart;
	pNeo->sHeapInfo.uiAllocAtom = uiAllocAtom;
	pNeo->sHeapInfo.uiSize = uiSize;

	*pResult = IMG_SUCCESS;
	return &(pNeo->sHeapInfo);
}

struct MMUHeapAlloc *IMGMMU_HeapAllocate(struct MMUHeap *pHeap, size_t uiSize,
		s32 *pResult)
{
	struct GEN_Heap *pInternalHeap = NULL;
	struct GEN_HeapAlloc *pNeo = NULL;

	IMG_ASSERT(pResult != NULL);
	IMG_ASSERT(pHeap != NULL);
	pInternalHeap = container_of(pHeap, struct GEN_Heap, sHeapInfo);

	if (uiSize%pHeap->uiAllocAtom != 0 || uiSize == 0) {
		MMU_LogError("invalid allocation size (0x%zx)\n", uiSize);
		*pResult = IMG_ERROR_INVALID_PARAMETERS;
		return NULL;
	}

	pNeo = (struct GEN_HeapAlloc *) IMG_CALLOC(1, sizeof(struct GEN_HeapAlloc));
	if (pNeo == NULL) {
		MMU_LogError("failed to allocate internal structure\n");
		*pResult = IMG_ERROR_MALLOC_FAILED;
		return NULL;
	}
	MMU_LogDebug("heap 0x%p alloc %u\n", pInternalHeap->pPool, uiSize);

	pNeo->sVirtualMem.uiVirtualAddress = gen_pool_alloc(pInternalHeap->pPool, uiSize);

	if (pNeo->sVirtualMem.uiVirtualAddress == 0) {
		MMU_LogError("failed to allocate from gen_pool_alloc\n");
		*pResult = IMG_ERROR_NOT_SUPPORTED;
		IMG_FREE(pNeo);
		return NULL;
	}

	// if base address is 0 we applied an offset
	if (pInternalHeap->sHeapInfo.uiVirtAddrStart == 0)
		pNeo->sVirtualMem.uiVirtualAddress -= pInternalHeap->sHeapInfo.uiAllocAtom;

	pNeo->sVirtualMem.uiAllocSize = uiSize;
	pNeo->pHeap = pInternalHeap;

	pInternalHeap->uiNAlloc++;

	//gen_pool_for_each_chunk(pInternalHeap->pPool, &pool_crawler, pInternalHeap->pPool);

	*pResult = IMG_SUCCESS;
	return &(pNeo->sVirtualMem);
}

s32 IMGMMU_HeapFree(struct MMUHeapAlloc *pAlloc)
{
	struct GEN_HeapAlloc *pInternalAlloc = NULL;
	uintptr_t uiAddress = 0;

	IMG_ASSERT(pAlloc != NULL);
	pInternalAlloc = container_of(pAlloc, struct GEN_HeapAlloc, sVirtualMem);

	IMG_ASSERT(pInternalAlloc->pHeap != NULL);
	IMG_ASSERT(pInternalAlloc->pHeap->pPool != NULL);
	IMG_ASSERT(pInternalAlloc->pHeap->uiNAlloc > 0);

	MMU_LogDebug("heap 0x%p free 0x%p %u B\n", pInternalAlloc->pHeap->pPool,
			pAlloc->uiVirtualAddress, pAlloc->uiAllocSize);

	uiAddress = pAlloc->uiVirtualAddress;
	// see the explanation in HeapCreate() to know why + uiAllocAtom
	if (pInternalAlloc->pHeap->sHeapInfo.uiVirtAddrStart == 0)
		uiAddress += pInternalAlloc->pHeap->sHeapInfo.uiAllocAtom;

	gen_pool_free(pInternalAlloc->pHeap->pPool, uiAddress, pAlloc->uiAllocSize);

	pInternalAlloc->pHeap->uiNAlloc--;

	IMG_FREE(pInternalAlloc);
	return IMG_SUCCESS;
}

s32 IMGMMU_HeapDestroy(struct MMUHeap *pHeap)
{
	struct GEN_Heap *pInternalHeap = NULL;

	IMG_ASSERT(pHeap != NULL);
	pInternalHeap = container_of(pHeap, struct GEN_Heap, sHeapInfo);

	if (pInternalHeap->uiNAlloc > 0) {
		MMU_LogError("destroying a heap with non-freed allocation\n");
		return IMG_ERROR_NOT_SUPPORTED;
	}

	if (pInternalHeap->pPool != NULL) {
		MMU_LogDebug("destroying genalloc pool 0x%p\n", pInternalHeap->pPool);
		gen_pool_destroy(pInternalHeap->pPool);
	}
	IMG_FREE(pInternalHeap);
	return IMG_SUCCESS;
}
