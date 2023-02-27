/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Low-level CPU initialisation
 * Based on arch/arm/kernel/head.S
 *
 * Copyright (C) 1994-2002 Russell King
 * Copyright (C) 2003-2012 ARM Ltd.
 * Authors:	Catalin Marinas <catalin.marinas@arm.com>
 *		Will Deacon <will.deacon@arm.com>
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/pgtable.h>

#include <asm/asm_pointer_auth.h>
#include <asm/assembler.h>
#include <asm/boot.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/cache.h>
#include <asm/cputype.h>
#include <asm/elf.h>
#include <asm/image.h>
#include <asm/kernel-pgtable.h>
#include <asm/kvm_arm.h>
#include <asm/memory.h>
#include <asm/pgtable-hwdef.h>
#include <asm/page.h>
#include <asm/scs.h>
#include <asm/smp.h>
#include <asm/sysreg.h>
#include <asm/thread_info.h>
#include <asm/virt.h>

#include "efi-header.S"

#define __PHYS_OFFSET	KERNEL_START

#if (PAGE_OFFSET & 0x1fffff) != 0
#error PAGE_OFFSET must be at least 2MB aligned
#endif

/*
 * Kernel startup entry point.
 * ---------------------------
 *
 * The requirements are:
 *   MMU = off, D-cache = off, I-cache = on or off,
 *   x0 = physical address to the FDT blob.
 *
 * This code is mostly position independent so you call this at
 * __pa(PAGE_OFFSET).
 *
 * Note that the callee-saved registers are used for storing variables
 * that are useful before the MMU is enabled. The allocations are described
 * in the entry routines.
 */
	__HEAD
_head:
	/*
	 * DO NOT MODIFY. Image header expected by Linux boot-loaders.
	 */
#ifdef CONFIG_EFI
	/*
	 * This add instruction has no meaningful effect except that
	 * its opcode forms the magic "MZ" signature required by UEFI.
	 */
	add	x13, x18, #0x16
	b	primary_entry
#else
	b	primary_entry			// branch to kernel start, magic
	.long	0				// reserved
#endif
	.quad	0				// Image load offset from start of RAM, little-endian
	le64sym	_kernel_size_le			// Effective size of kernel image, little-endian
	le64sym	_kernel_flags_le		// Informative flags, little-endian
	.quad	0				// reserved
	.quad	0				// reserved
	.quad	0				// reserved
	.ascii	ARM64_IMAGE_MAGIC		// Magic number
#ifdef CONFIG_EFI
	.long	pe_header - _head		// Offset to the PE header.

pe_header:
	__EFI_PE_HEADER
#else
	.long	0				// reserved
#endif

	__INIT

	/*
	 * The following callee saved general purpose registers are used on the
	 * primary lowlevel boot path:
	 *
	 *  Register   Scope                      Purpose
	 *  x21        primary_entry() .. start_kernel()        FDT pointer passed at boot in x0
	 *  x23        primary_entry() .. start_kernel()        physical misalignment/KASLR offset
	 *  x28        __create_page_tables()                   callee preserved temp register
	 *  x19/x20    __primary_switch()                       callee preserved temp registers
	 *  x24        __primary_switch() .. relocate_kernel()  current RELR displacement
	 */
SYM_CODE_START(primary_entry)
	bl	preserve_boot_args		//保留引导加载程序中传递的参数到boot_args中
	bl	el2_setup				// 判断目前是EL1还是EL2，
									//如果是EL1就简单了，配置sctlr_el1寄存器就好了。
									//如果是EL2就复杂了，需要配置sctlr_el2寄存器，配置内存，hcr，gic
	adrp	x23, __PHYS_OFFSET
	and	x23, x23, MIN_KIMG_ALIGN - 1	// KASLR offset, defaults to 0
	bl	set_cpu_boot_mode_flag		//把其他cpu都配置成跟cpu0同样的特权等级
	bl	__create_page_tables		//创建页表映射
	/*
	 * The following calls CPU setup code, see arch/arm64/mm/proc.S for
	 * details.
	 * On return, the CPU will be ready for the MMU to be turned on and
	 * the TCR will have been set.
	 */
	bl	__cpu_setup			// 初始化处理器以打开MMU。
	b	__primary_switch	//设置TTBR0和TTBR1，使能MMU，将kernel image重定位，跳转到__primary_switched

SYM_CODE_END(primary_entry)

/*
 * Preserve the arguments passed by the bootloader in x0 .. x3
 */
SYM_CODE_START_LOCAL(preserve_boot_args)
	mov	x21, x0			// x21=FDT，将FDT的地址暂存在x21寄存器中，释放出x0以便后续做临时变量使用

	adr_l	x0, boot_args			// x0保存了boot_args变量的地址
	stp	x21, x1, [x0]			// 保存x0和x1的值到boot_args[0]和boot_args[1]
	stp	x2, x3, [x0, #16]		// 保存x2和x3的值到boot_args[2]和boot_args[3]
	
	dmb	sy				// needed before dc ivac with
						// MMU off

	mov	x1, #0x20			// 4 x 8 bytes
	b	__inval_dcache_area		// 让[boot_args，boot_args+#0x20]的内存数据缓存失效
SYM_CODE_END(preserve_boot_args)

/*
 * Macro to create a table entry to the next page.
 *
 *	tbl:	page table address
 *	virt:	virtual address
 *	shift:	#imm page table shift
 *	ptrs:	#imm pointers per table page
 *
 * Preserves:	virt
 * Corrupts:	ptrs, tmp1, tmp2
 * Returns:	tbl -> next level table page address
 */
	.macro	create_table_entry, tbl, virt, shift, ptrs, tmp1, tmp2
	add	\tmp1, \tbl, #PAGE_SIZE
	phys_to_pte \tmp2, \tmp1
	orr	\tmp2, \tmp2, #PMD_TYPE_TABLE	// address of next table and entry type
	lsr	\tmp1, \virt, #\shift
	sub	\ptrs, \ptrs, #1
	and	\tmp1, \tmp1, \ptrs		// table index
	str	\tmp2, [\tbl, \tmp1, lsl #3]
	add	\tbl, \tbl, #PAGE_SIZE		// next level table page
	.endm

/*
 * Macro to populate page table entries, these entries can be pointers to the next level
 * or last level entries pointing to physical memory.
 *
 *	tbl:	page table address
 *	rtbl:	pointer to page table or physical memory
 *	index:	start index to write
 *	eindex:	end index to write - [index, eindex] written to
 *	flags:	flags for pagetable entry to or in
 *	inc:	increment to rtbl between each entry
 *	tmp1:	temporary variable
 *
 * Preserves:	tbl, eindex, flags, inc
 * Corrupts:	index, tmp1
 * Returns:	rtbl
 */
	.macro populate_entries, tbl, rtbl, index, eindex, flags, inc, tmp1
.Lpe\@:	phys_to_pte \tmp1, \rtbl
	orr	\tmp1, \tmp1, \flags	// tmp1 = table entry
	str	\tmp1, [\tbl, \index, lsl #3]
	add	\rtbl, \rtbl, \inc	// rtbl = pa next level
	add	\index, \index, #1
	cmp	\index, \eindex
	b.ls	.Lpe\@
	.endm

/*
 * Compute indices of table entries from virtual address range. If multiple entries
 * were needed in the previous page table level then the next page table level is assumed
 * to be composed of multiple pages. (This effectively scales the end index).
 *
 *	vstart:	virtual address of start of range
 *	vend:	virtual address of end of range - we map [vstart, vend]
 *	shift:	shift used to transform virtual address into index
 *	ptrs:	number of entries in page table
 *	istart:	index in table corresponding to vstart
 *	iend:	index in table corresponding to vend
 *	count:	On entry: how many extra entries were required in previous level, scales
 *			  our end index.
 *		On exit: returns how many extra entries required for next page table level
 *
 * Preserves:	vstart, vend, shift, ptrs
 * Returns:	istart, iend, count
 */
	.macro compute_indices, vstart, vend, shift, ptrs, istart, iend, count
	lsr	\iend, \vend, \shift
	mov	\istart, \ptrs
	sub	\istart, \istart, #1
	and	\iend, \iend, \istart	// iend = (vend >> shift) & (ptrs - 1)
	mov	\istart, \ptrs
	mul	\istart, \istart, \count
	add	\iend, \iend, \istart	// iend += (count - 1) * ptrs
					// our entries span multiple tables

	lsr	\istart, \vstart, \shift
	mov	\count, \ptrs
	sub	\count, \count, #1
	and	\istart, \istart, \count

	sub	\count, \iend, \istart
	.endm

/*
 * Map memory for specified virtual address range. Each level of page table needed supports
 * multiple entries. If a level requires n entries the next page table level is assumed to be
 * formed from n pages.
 *
 *	tbl:	location of page table
 *	rtbl:	address to be used for first level page table entry (typically tbl + PAGE_SIZE)
 *	vstart:	virtual address of start of range
 *	vend:	virtual address of end of range - we map [vstart, vend - 1]
 *	flags:	flags to use to map last level entries
 *	phys:	physical address corresponding to vstart - physical memory is contiguous
 *	pgds:	the number of pgd entries
 *
 * Temporaries:	istart, iend, tmp, count, sv - these need to be different registers
 * Preserves:	vstart, flags
 * Corrupts:	tbl, rtbl, vend, istart, iend, tmp, count, sv
 */
	.macro map_memory, tbl, rtbl, vstart, vend, flags, phys, pgds, istart, iend, tmp, count, sv
	sub \vend, \vend, #1	//虚拟地址减一
	add \rtbl, \tbl, #PAGE_SIZE	//第一级页表项的地址，是页全局基地址的下一页
	mov \sv, \rtbl
	mov \count, #0
	//compute_indices是用来计算vstart和vend对应的 pgtable level的index的，两者之差保存在count中
	compute_indices \vstart, \vend, #PGDIR_SHIFT, \pgds, \istart, \iend, \count
	//populate_entries最终建立指向下一级的映射或者last level映射
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
	mov \sv, \rtbl

#if SWAPPER_PGTABLE_LEVELS > 3
	compute_indices \vstart, \vend, #PUD_SHIFT, #PTRS_PER_PUD, \istart, \iend, \count
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
	mov \sv, \rtbl
#endif

#if SWAPPER_PGTABLE_LEVELS > 2
	compute_indices \vstart, \vend, #SWAPPER_TABLE_SHIFT, #PTRS_PER_PMD, \istart, \iend, \count
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
#endif

	compute_indices \vstart, \vend, #SWAPPER_BLOCK_SHIFT, #PTRS_PER_PTE, \istart, \iend, \count
	bic \count, \phys, #SWAPPER_BLOCK_SIZE - 1
	populate_entries \tbl, \count, \istart, \iend, \flags, #SWAPPER_BLOCK_SIZE, \tmp
	.endm

/*
 * Setup the initial page tables. We only setup the barest amount which is
 * required to get the kernel running. The following sections are required:
 *   - identity mapping to enable the MMU (low address, TTBR0)
 *   - first few MB of the kernel linear mapping to jump to once the MMU has
 *     been enabled
 */
SYM_FUNC_START_LOCAL(__create_page_tables)
	mov	x28, lr	//lr是连接寄存器

	/*
	 * Invalidate the init page tables to avoid potential dirty cache lines
	 * being evicted. Other page tables are allocated in rodata as part of
	 * the kernel image, and thus are clean to the PoC per the boot
	 * protocol.
	 */
	adrp	x0, init_pg_dir	//获取内核init页表的基地址
	adrp	x1, init_pg_end	//获取内核init页表的基地址
	sub	x1, x1, x0
	bl	__inval_dcache_area	//清除Dcache

	/*
	 * Clear the init page tables.
	 */
	//把init_pg_dir到init_pg_end这段内存清零
	//也就是把内核页表清零
	adrp	x0, init_pg_dir
	adrp	x1, init_pg_end
	sub	x1, x1, x0
1:	stp	xzr, xzr, [x0], #16	//把0写入以x0为地址的内存中，然后x0自增16
	stp	xzr, xzr, [x0], #16
	stp	xzr, xzr, [x0], #16
	stp	xzr, xzr, [x0], #16
	subs	x1, x1, #64
	b.ne	1b

	mov	x7, SWAPPER_MM_MMUFLAGS

	/*
	 * Create the identity mapping.
	 */
	//创建恒等映射，也就是虚拟地址和物理地址相同
	adrp	x0, idmap_pg_dir	//恒等映射的页全局目录的起始地址
	adrp	x3, __idmap_text_start		// 恒等映射代码节的起始地址

#ifdef CONFIG_ARM64_VA_BITS_52	//不支持，不用看
	mrs_s	x6, SYS_ID_AA64MMFR2_EL1
	and	x6, x6, #(0xf << ID_AA64MMFR2_LVA_SHIFT)
	mov	x5, #52
	cbnz	x6, 1f
#endif
	mov	x5, #VA_BITS_MIN	//虚拟地址位数
1:
	adr_l	x6, vabits_actual	//获取PC到vabits_actual的相对偏移地址
	str	x5, [x6]		//定位PC的虚拟地址
	dmb	sy
	dc	ivac, x6		// 使x6所在的dcache失效

	/*
	 * VA_BITS may be too small to allow for an ID mapping to be created
	 * that covers system RAM if that is located sufficiently high in the
	 * physical address space. So for the ID map, use an extended virtual
	 * range in that case, and configure an additional translation level
	 * if needed.
	 *
	 * Calculate the maximum allowed value for TCR_EL1.T0SZ so that the
	 * entire ID map region can be mapped. As T0SZ == (64 - #bits used),
	 * this number conveniently equals the number of leading zeroes in
	 * the physical address of __idmap_text_end.
	 */
	//T0SZ决定了输出的物理地址位数，这里查看其是否足够覆盖物理地址
	adrp	x5, __idmap_text_end	//获取__idmap_text_end的页基地址
	clz	x5, x5	//计算x5高位0的个数
	cmp	x5, TCR_T0SZ(VA_BITS_MIN) // default T0SZ small enough?
	b.ge	1f			// .. then skip VA range extension

	adr_l	x6, idmap_t0sz	//计算idmap_t0sz的页内偏移
	str	x5, [x6]		//把x5的数据写入以x6为地址的内存中
	dmb	sy
	dc	ivac, x6		// Invalidate potentially stale cache line

#if (VA_BITS < 48)
#define EXTRA_SHIFT	(PGDIR_SHIFT + PAGE_SHIFT - 3)
#define EXTRA_PTRS	(1 << (PHYS_MASK_SHIFT - EXTRA_SHIFT))

	/*
	 * If VA_BITS < 48, we have to configure an additional table level.
	 * First, we have to verify our assumption that the current value of
	 * VA_BITS was chosen such that all translation levels are fully
	 * utilised, and that lowering T0SZ will always result in an additional
	 * translation level to be configured.
	 */
#if VA_BITS != EXTRA_SHIFT
#error "Mismatch between VA_BITS and page size/number of translation levels"
#endif

	mov	x4, EXTRA_PTRS
	create_table_entry x0, x3, EXTRA_SHIFT, x4, x5, x6	//配置额外的页表
#else
	/*
	 * If VA_BITS == 48, we don't have to configure an additional
	 * translation level, but the top-level table has more entries.
	 */
	mov	x4, #1 << (PHYS_MASK_SHIFT - PGDIR_SHIFT)
	str_l	x4, idmap_ptrs_per_pgd, x5
#endif
1:
	ldr_l	x4, idmap_ptrs_per_pgd	//取idmap_ptrs_per_pgd的页内偏移到x4中
	mov	x5, x3				// __pa(__idmap_text_start)
	adr_l	x6, __idmap_text_end		// __pa(__idmap_text_end)

	map_memory x0, x1, x3, x6, x7, x3, x4, x10, x11, x12, x13, x14	//映射，写入页表

	/*
	 * Map the kernel image (starting with PHYS_OFFSET).
	 */
	//内核镜像映射
	adrp	x0, init_pg_dir			//页表基地址
	mov_q	x5, KIMAGE_VADDR		// 代码段的虚拟地址
	add	x5, x5, x23			// add KASLR displacement
	mov	x4, PTRS_PER_PGD	//PGD表项的数量
	adrp	x6, _end			// 代码段的物理地址末端
	adrp	x3, _text			// 代码段的物理地址起始位置
	sub	x6, x6, x3			// 代码段长度
	add	x6, x6, x5			// 代码段虚拟地址末端

	map_memory x0, x1, x5, x6, x7, x3, x4, x10, x11, x12, x13, x14	//创建内核镜像的映射关系

	/*
	 * Since the page tables have been populated with non-cacheable
	 * accesses (MMU disabled), invalidate those tables again to
	 * remove any speculatively loaded cache lines.
	 */
	dmb	sy

	adrp	x0, idmap_pg_dir
	adrp	x1, idmap_pg_end
	sub	x1, x1, x0
	bl	__inval_dcache_area	//使dcache失效

	adrp	x0, init_pg_dir
	adrp	x1, init_pg_end
	sub	x1, x1, x0
	bl	__inval_dcache_area	//使dcache失效

	ret	x28	//返回
SYM_FUNC_END(__create_page_tables)

/*
 * The following fragment of code is executed with the MMU enabled.
 *
 *   x0 = __PHYS_OFFSET
 */
SYM_FUNC_START_LOCAL(__primary_switched)
	adrp	x4, init_thread_union	//init_thread_union地址保存在x4中，它存放了init进程结构体
	add	sp, x4, #THREAD_SIZE	//设置sp指针为init_thread_union偏移THREAD_SIZE
	adr_l	x5, init_task		//init_task地址保存在x5
	msr	sp_el0, x5			//保存当前进程描述符到sp_el0，使用用户态的堆栈，说明是用户态程序

#ifdef CONFIG_ARM64_PTR_AUTH
	__ptrauth_keys_init_cpu	x5, x6, x7, x8
#endif

	adr_l	x8, vectors			// 读取vectors的地址
	msr	vbar_el1, x8			// 设置异常向量表
	isb

	stp	xzr, x30, [sp, #-16]!	//把将xzr和保存在x30中的链接地址入栈
	mov	x29, sp		//将栈指针保存到x29

#ifdef CONFIG_SHADOW_CALL_STACK
	adr_l	scs_sp, init_shadow_call_stack	// Set shadow call stack
#endif

	str_l	x21, __fdt_pointer, x5		//将FDT地址保存到__fdt_pointer变量

	ldr_l	x4, kimage_vaddr		// Save the offset between
	sub	x4, x4, x0			// the kernel virtual and
	str_l	x4, kimage_voffset, x5		//将kimage的虚拟地址和物理地址的偏移保存到kimage_voffset中

	// Clear BSS
	adr_l	x0, __bss_start
	mov	x1, xzr
	adr_l	x2, __bss_stop
	sub	x2, x2, x0
	bl	__pi_memset		//清理bss段数据
	dsb	ishst				// Make zero page visible to PTW

#ifdef CONFIG_KASAN
	bl	kasan_early_init
#endif
#ifdef CONFIG_RANDOMIZE_BASE
	tst	x23, ~(MIN_KIMG_ALIGN - 1)	// already running randomized?
	b.ne	0f
	mov	x0, x21				// pass FDT address in x0
	bl	kaslr_early_init		// parse FDT for KASLR options
	cbz	x0, 0f				// KASLR disabled? just proceed
	orr	x23, x23, x0			// record KASLR offset
	ldp	x29, x30, [sp], #16		// we must enable KASLR, return
	ret					// to __primary_switch()
0:
#endif
	add	sp, sp, #16		//sp加一
	mov	x29, #0			
	mov	x30, #0
	b	start_kernel	//跳转到start_kernel
SYM_FUNC_END(__primary_switched)

	.pushsection ".rodata", "a"
SYM_DATA_START(kimage_vaddr)
	.quad		_text
SYM_DATA_END(kimage_vaddr)
EXPORT_SYMBOL(kimage_vaddr)
	.popsection

/*
 * end early head section, begin head code that is also used for
 * hotplug and needs to have the same protections as the text region
 */
	.section ".idmap.text","awx"

/*
 * If we're fortunate enough to boot at EL2, ensure that the world is
 * sane before dropping to EL1.
 *
 * Returns either BOOT_CPU_MODE_EL1 or BOOT_CPU_MODE_EL2 in w0 if
 * booted in EL1 or EL2 respectively.
 */
SYM_FUNC_START(el2_setup)
	msr	SPsel, #1			//往SPsel写1，说明使用SP_EL0
	mrs	x0, CurrentEL		//获取当前特权等级
	cmp	x0, #CurrentEL_EL2	//看看是不是特权等级是否为EL2
	b.eq	1f				//如果是，就跳转到1f
	mov_q	x0, (SCTLR_EL1_RES1 | ENDIAN_SET_EL1)//
	msr	sctlr_el1, x0		//配置EL1的系统控制寄存器
	mov	w0, #BOOT_CPU_MODE_EL1		// 返回值存在w0寄存器中
	isb								//内存屏障
	ret								//返回

	//这里说明当前等级是EL2
1:	mov_q	x0, (SCTLR_EL2_RES1 | ENDIAN_SET_EL2)
	msr	sctlr_el2, x0		//配置EL2的系统控制寄存器

#ifdef CONFIG_ARM64_VHE
	/*
	 * Check for VHE being present. For the rest of the EL2 setup,
	 * x2 being non-zero indicates that we do have VHE, and that the
	 * kernel is intended to run at EL2.
	 */
	mrs	x2, id_aa64mmfr1_el1	//配置内存模式寄存器
	ubfx	x2, x2, #ID_AA64MMFR1_VHE_SHIFT, #4	//把虚拟机扩展支持位提取出来
#else
	mov	x2, xzr
#endif

	/* Hyp configuration. *///Hypervisor配置寄存器
	mov_q	x0, HCR_HOST_NVHE_FLAGS	//访问到EL2的指令转发到未定义指令
	cbz	x2, set_hcr		//x2为0（不支持虚拟机扩展，也就是传统分裂模式）则跳转到set_hcr
	mov_q	x0, HCR_HOST_VHE_FLAGS	//设置中断路由到EL2、启动EL2设施、
set_hcr://虚拟机扩展模式
	msr	hcr_el2, x0		//写入hcr_el2
	isb					//内存屏障

	/*
	 * Allow Non-secure EL1 and EL0 to access physical timer and counter.
	 * This is not necessary for VHE, since the host kernel runs in EL2,
	 * and EL0 accesses are configured in the later stage of boot process.
	 * Note that when HCR_EL2.E2H == 1, CNTHCTL_EL2 has the same bit layout
	 * as CNTKCTL_EL1, and CNTKCTL_EL1 accessing instructions are redefined
	 * to access CNTHCTL_EL2. This allows the kernel designed to run at EL1
	 * to transparently mess with the EL0 bits via CNTKCTL_EL1 access in
	 * EL2.
	 */
	cbnz	x2, 1f			//x2为0（不支持虚拟机扩展）则跳转到1f
	mrs	x0, cnthctl_el2		//读取Hypervisor控制的计数寄存器
	orr	x0, x0, #3			// Enable EL1 physical timers
	msr	cnthctl_el2, x0
1:
	msr	cntvoff_el2, xzr		// 物理计数器和虚拟计数器一致，不偏移

#ifdef CONFIG_ARM_GIC_V3
	/* GICv3 system register access */
	mrs	x0, id_aa64pfr0_el1		//读取处理器特性寄存器
	ubfx	x0, x0, #ID_AA64PFR0_GIC_SHIFT, #4
	cbz	x0, 3f		//如果不是gic3或者4.0。跳转到3f

	//说明gic版本为3.0或者4.0
	mrs_s	x0, SYS_ICC_SRE_EL2		//读取中断控制器启用寄存器
	orr	x0, x0, #ICC_SRE_EL2_SRE	// Set ICC_SRE_EL2.SRE==1
	orr	x0, x0, #ICC_SRE_EL2_ENABLE	// Set ICC_SRE_EL2.Enable==1
	msr_s	SYS_ICC_SRE_EL2, x0
	isb					// Make sure SRE is now set
	mrs_s	x0, SYS_ICC_SRE_EL2		// Read SRE back,
	tbz	x0, #0, 3f			// and check that it sticks
	msr_s	SYS_ICH_HCR_EL2, xzr		// Reset ICC_HCR_EL2 to defaults

3:
#endif

	/* Populate ID registers. */
	//填充虚拟机ID寄存器
	mrs	x0, midr_el1
	mrs	x1, mpidr_el1
	msr	vpidr_el2, x0	//虚拟化处理器ID寄存器
	msr	vmpidr_el2, x1	//虚拟化多处理器ID寄存器

#ifdef CONFIG_COMPAT
	msr	hstr_el2, xzr			// Disable CP15 traps to EL2
#endif

	/* EL2 debug */	
	mrs	x1, id_aa64dfr0_el1		//读取AArch64调试特性寄存器
	sbfx	x0, x1, #ID_AA64DFR0_PMUVER_SHIFT, #4
	cmp	x0, #1
	b.lt	4f				// Skip if no PMU present
	mrs	x0, pmcr_el0			//读取性能监视器控制寄存器
	ubfx	x0, x0, #11, #5			//允许EL2访问性能监视器控制寄存器
4:
	csel	x3, xzr, x0, lt			// all PMU counters from EL1

	/* Statistical profiling */
	ubfx	x0, x1, #ID_AA64DFR0_PMSVER_SHIFT, #4
	cbz	x0, 7f				// Skip if SPE not present
	cbnz	x2, 6f				// VHE?
	mrs_s	x4, SYS_PMBIDR_EL1		// If SPE available at EL2,找不到该寄存器
	and	x4, x4, #(1 << SYS_PMBIDR_EL1_P_SHIFT)
	cbnz	x4, 5f				// then permit sampling of physical
	mov	x4, #(1 << SYS_PMSCR_EL2_PCT_SHIFT | \
		      1 << SYS_PMSCR_EL2_PA_SHIFT)
	msr_s	SYS_PMSCR_EL2, x4		// addresses and physical counter
5:
	mov	x1, #(MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT)
	orr	x3, x3, x1			// If we don't have VHE, then
	b	7f				// use EL1&0 translation.
6:						// For VHE, use EL2 translation
	orr	x3, x3, #MDCR_EL2_TPMS		// and disable access from EL1
7:
	msr	mdcr_el2, x3			// Configure debug traps

	/* LORegions */
	mrs	x1, id_aa64mmfr1_el1	//AArch64内存模型特征寄存器
	ubfx	x0, x1, #ID_AA64MMFR1_LOR_SHIFT, 4
	cbz	x0, 1f
	msr_s	SYS_LORC_EL1, xzr
1:

	/* Stage-2 translation */
	msr	vttbr_el2, xzr		//虚拟化转换表基寄存器

	cbz	x2, install_el2_stub

	mov	w0, #BOOT_CPU_MODE_EL2		// This CPU booted in EL2
	isb
	ret

SYM_INNER_LABEL(install_el2_stub, SYM_L_LOCAL)
	/*
	 * When VHE is not in use, early init of EL2 and EL1 needs to be
	 * done here.
	 * When VHE _is_ in use, EL1 will not be used in the host and
	 * requires no configuration, and all non-hyp-specific EL2 setup
	 * will be done via the _EL1 system register aliases in __cpu_setup.
	 */
	mov_q	x0, (SCTLR_EL1_RES1 | ENDIAN_SET_EL1)
	msr	sctlr_el1, x0

	/* Coprocessor traps. */
	mov	x0, #0x33ff
	msr	cptr_el2, x0			// Disable copro. traps to EL2

	/* SVE register access */
	mrs	x1, id_aa64pfr0_el1
	ubfx	x1, x1, #ID_AA64PFR0_SVE_SHIFT, #4
	cbz	x1, 7f

	bic	x0, x0, #CPTR_EL2_TZ		// Also disable SVE traps
	msr	cptr_el2, x0			// Disable copro. traps to EL2
	isb
	mov	x1, #ZCR_ELx_LEN_MASK		// SVE: Enable full vector
	msr_s	SYS_ZCR_EL2, x1			// length for EL1.

	/* Hypervisor stub */
7:	adr_l	x0, __hyp_stub_vectors
	msr	vbar_el2, x0

	/* spsr */
	mov	x0, #(PSR_F_BIT | PSR_I_BIT | PSR_A_BIT | PSR_D_BIT |\
		      PSR_MODE_EL1h)
	msr	spsr_el2, x0
	msr	elr_el2, lr
	mov	w0, #BOOT_CPU_MODE_EL2		// This CPU booted in EL2
	eret
SYM_FUNC_END(el2_setup)

/*
 * Sets the __boot_cpu_mode flag depending on the CPU boot mode passed
 * in w0. See arch/arm64/include/asm/virt.h for more info.
 */
SYM_FUNC_START_LOCAL(set_cpu_boot_mode_flag)
	adr_l	x1, __boot_cpu_mode	//把__boot_cpu_mode地址赋值给x1
	cmp	w0, #BOOT_CPU_MODE_EL2	//如果当前cpu处于EL2
	b.ne	1f					//跳转到1
	add	x1, x1, #4				//当前cpu在EL1，使用__boot_cpu_mode[1]
	//当前cpu在EL2，使用__boot_cpu_mode[0]
1:	str	w0, [x1]			//将w0写入__boot_cpu_mode
	dmb	sy
	dc	ivac, x1			// Invalidate potentially stale cache line
	ret
SYM_FUNC_END(set_cpu_boot_mode_flag)

/*
 * These values are written with the MMU off, but read with the MMU on.
 * Writers will invalidate the corresponding address, discarding up to a
 * 'Cache Writeback Granule' (CWG) worth of data. The linker script ensures
 * sufficient alignment that the CWG doesn't overlap another section.
 */
	.pushsection ".mmuoff.data.write", "aw"
/*
 * We need to find out the CPU boot mode long after boot, so we need to
 * store it in a writable variable.
 *
 * This is not in .bss, because we set it sufficiently early that the boot-time
 * zeroing of .bss would clobber it.
 */
SYM_DATA_START(__boot_cpu_mode)
	.long	BOOT_CPU_MODE_EL2
	.long	BOOT_CPU_MODE_EL1
SYM_DATA_END(__boot_cpu_mode)
/*
 * The booting CPU updates the failed status @__early_cpu_boot_status,
 * with MMU turned off.
 */
SYM_DATA_START(__early_cpu_boot_status)
	.quad 	0
SYM_DATA_END(__early_cpu_boot_status)

	.popsection

	/*
	 * This provides a "holding pen" for platforms to hold all secondary
	 * cores are held until we're ready for them to initialise.
	 */
SYM_FUNC_START(secondary_holding_pen)
	bl	el2_setup			// Drop to EL1, w0=cpu_boot_mode
	bl	set_cpu_boot_mode_flag
	mrs	x0, mpidr_el1
	mov_q	x1, MPIDR_HWID_BITMASK
	and	x0, x0, x1
	adr_l	x3, secondary_holding_pen_release
pen:	ldr	x4, [x3]
	cmp	x4, x0
	b.eq	secondary_startup
	wfe
	b	pen
SYM_FUNC_END(secondary_holding_pen)

	/*
	 * Secondary entry point that jumps straight into the kernel. Only to
	 * be used where CPUs are brought online dynamically by the kernel.
	 */
SYM_FUNC_START(secondary_entry)
	bl	el2_setup			// Drop to EL1
	bl	set_cpu_boot_mode_flag
	b	secondary_startup
SYM_FUNC_END(secondary_entry)

SYM_FUNC_START_LOCAL(secondary_startup)
	/*
	 * Common entry point for secondary CPUs.
	 */
	bl	__cpu_secondary_check52bitva
	bl	__cpu_setup			// initialise processor
	adrp	x1, swapper_pg_dir
	bl	__enable_mmu
	ldr	x8, =__secondary_switched
	br	x8
SYM_FUNC_END(secondary_startup)

SYM_FUNC_START_LOCAL(__secondary_switched)
	adr_l	x5, vectors
	msr	vbar_el1, x5
	isb

	adr_l	x0, secondary_data
	ldr	x1, [x0, #CPU_BOOT_STACK]	// get secondary_data.stack
	cbz	x1, __secondary_too_slow
	mov	sp, x1
	ldr	x2, [x0, #CPU_BOOT_TASK]
	cbz	x2, __secondary_too_slow
	msr	sp_el0, x2
	scs_load x2, x3
	mov	x29, #0
	mov	x30, #0

#ifdef CONFIG_ARM64_PTR_AUTH
	ptrauth_keys_init_cpu x2, x3, x4, x5
#endif

	b	secondary_start_kernel
SYM_FUNC_END(__secondary_switched)

SYM_FUNC_START_LOCAL(__secondary_too_slow)
	wfe
	wfi
	b	__secondary_too_slow
SYM_FUNC_END(__secondary_too_slow)

/*
 * The booting CPU updates the failed status @__early_cpu_boot_status,
 * with MMU turned off.
 *
 * update_early_cpu_boot_status tmp, status
 *  - Corrupts tmp1, tmp2
 *  - Writes 'status' to __early_cpu_boot_status and makes sure
 *    it is committed to memory.
 */

	.macro	update_early_cpu_boot_status status, tmp1, tmp2
	mov	\tmp2, #\status
	adr_l	\tmp1, __early_cpu_boot_status
	str	\tmp2, [\tmp1]
	dmb	sy
	dc	ivac, \tmp1			// Invalidate potentially stale cache line
	.endm

/*
 * Enable the MMU.
 *
 *  x0  = SCTLR_EL1 value for turning on the MMU.
 *  x1  = TTBR1_EL1 value
 *
 * Returns to the caller via x30/lr. This requires the caller to be covered
 * by the .idmap.text section.
 *
 * Checks if the selected granule size is supported by the CPU.
 * If it isn't, park the CPU
 */
SYM_FUNC_START(__enable_mmu)
	mrs	x2, ID_AA64MMFR0_EL1	//读取内存模型特征寄存器
	ubfx	x2, x2, #ID_AA64MMFR0_TGRAN_SHIFT, 4	//提取28到31这4位
	cmp     x2, #ID_AA64MMFR0_TGRAN_SUPPORTED_MIN	//如果支持4k页
	b.lt    __no_granule_support		//卡死
	cmp     x2, #ID_AA64MMFR0_TGRAN_SUPPORTED_MAX	//如果不支持4k页
	b.gt    __no_granule_support		//卡死
	//只有4KB粒度支持52位输入输出地址
	update_early_cpu_boot_status 0, x2, x3	//启动中的CPU更新失败状态
	adrp	x2, idmap_pg_dir	//读取内核页全局目录页表到x2
	phys_to_ttbr x1, x1
	phys_to_ttbr x2, x2
	msr	ttbr0_el1, x2			//内核页全局目录页表写入ttbr0_el1
	offset_ttbr1 x1, x3
	msr	ttbr1_el1, x1			//内核镜像的init目录页表写入ttbr1_el1
	isb
	msr	sctlr_el1, x0	//把SCTLR_EL1_SET写入sctlr_el1寄存器，之前保存在x0
	isb
	/*
	 * Invalidate the local I-cache so that any instructions fetched
	 * speculatively from the PoC are discarded, since they may have
	 * been dynamically patched at the PoU.
	 */
	ic	iallu	//icache失效
	dsb	nsh		//内存屏障
	isb
	ret
SYM_FUNC_END(__enable_mmu)

SYM_FUNC_START(__cpu_secondary_check52bitva)
#ifdef CONFIG_ARM64_VA_BITS_52
	ldr_l	x0, vabits_actual
	cmp	x0, #52
	b.ne	2f

	mrs_s	x0, SYS_ID_AA64MMFR2_EL1
	and	x0, x0, #(0xf << ID_AA64MMFR2_LVA_SHIFT)
	cbnz	x0, 2f

	update_early_cpu_boot_status \
		CPU_STUCK_IN_KERNEL | CPU_STUCK_REASON_52_BIT_VA, x0, x1
1:	wfe
	wfi
	b	1b

#endif
2:	ret
SYM_FUNC_END(__cpu_secondary_check52bitva)

SYM_FUNC_START_LOCAL(__no_granule_support)
	/* Indicate that this CPU can't boot and is stuck in the kernel */
	update_early_cpu_boot_status \
		CPU_STUCK_IN_KERNEL | CPU_STUCK_REASON_NO_GRAN, x1, x2
1:
	wfe
	wfi
	b	1b
SYM_FUNC_END(__no_granule_support)

#ifdef CONFIG_RELOCATABLE
SYM_FUNC_START_LOCAL(__relocate_kernel)
	/*
	 * Iterate over each entry in the relocation table, and apply the
	 * relocations in place.
	 */
	ldr	w9, =__rela_offset		// offset to reloc table
	ldr	w10, =__rela_size		// size of reloc table

	mov_q	x11, KIMAGE_VADDR		// default virtual offset
	add	x11, x11, x23			// actual virtual offset
	add	x9, x9, x11			// __va(.rela)
	add	x10, x9, x10			// __va(.rela) + sizeof(.rela)

0:	cmp	x9, x10
	b.hs	1f
	ldp	x12, x13, [x9], #24
	ldr	x14, [x9, #-8]
	cmp	w13, #R_AARCH64_RELATIVE
	b.ne	0b
	add	x14, x14, x23			// relocate
	str	x14, [x12, x23]
	b	0b

1:
#ifdef CONFIG_RELR
	/*
	 * Apply RELR relocations.
	 *
	 * RELR is a compressed format for storing relative relocations. The
	 * encoded sequence of entries looks like:
	 * [ AAAAAAAA BBBBBBB1 BBBBBBB1 ... AAAAAAAA BBBBBB1 ... ]
	 *
	 * i.e. start with an address, followed by any number of bitmaps. The
	 * address entry encodes 1 relocation. The subsequent bitmap entries
	 * encode up to 63 relocations each, at subsequent offsets following
	 * the last address entry.
	 *
	 * The bitmap entries must have 1 in the least significant bit. The
	 * assumption here is that an address cannot have 1 in lsb. Odd
	 * addresses are not supported. Any odd addresses are stored in the RELA
	 * section, which is handled above.
	 *
	 * Excluding the least significant bit in the bitmap, each non-zero
	 * bit in the bitmap represents a relocation to be applied to
	 * a corresponding machine word that follows the base address
	 * word. The second least significant bit represents the machine
	 * word immediately following the initial address, and each bit
	 * that follows represents the next word, in linear order. As such,
	 * a single bitmap can encode up to 63 relocations in a 64-bit object.
	 *
	 * In this implementation we store the address of the next RELR table
	 * entry in x9, the address being relocated by the current address or
	 * bitmap entry in x13 and the address being relocated by the current
	 * bit in x14.
	 *
	 * Because addends are stored in place in the binary, RELR relocations
	 * cannot be applied idempotently. We use x24 to keep track of the
	 * currently applied displacement so that we can correctly relocate if
	 * __relocate_kernel is called twice with non-zero displacements (i.e.
	 * if there is both a physical misalignment and a KASLR displacement).
	 */
	ldr	w9, =__relr_offset		// offset to reloc table
	ldr	w10, =__relr_size		// size of reloc table
	add	x9, x9, x11			// __va(.relr)
	add	x10, x9, x10			// __va(.relr) + sizeof(.relr)

	sub	x15, x23, x24			// delta from previous offset
	cbz	x15, 7f				// nothing to do if unchanged
	mov	x24, x23			// save new offset

2:	cmp	x9, x10
	b.hs	7f
	ldr	x11, [x9], #8
	tbnz	x11, #0, 3f			// branch to handle bitmaps
	add	x13, x11, x23
	ldr	x12, [x13]			// relocate address entry
	add	x12, x12, x15
	str	x12, [x13], #8			// adjust to start of bitmap
	b	2b

3:	mov	x14, x13
4:	lsr	x11, x11, #1
	cbz	x11, 6f
	tbz	x11, #0, 5f			// skip bit if not set
	ldr	x12, [x14]			// relocate bit
	add	x12, x12, x15
	str	x12, [x14]

5:	add	x14, x14, #8			// move to next bit's address
	b	4b

6:	/*
	 * Move to the next bitmap's address. 8 is the word size, and 63 is the
	 * number of significant bits in a bitmap entry.
	 */
	add	x13, x13, #(8 * 63)
	b	2b

7:
#endif
	ret

SYM_FUNC_END(__relocate_kernel)
#endif

SYM_FUNC_START_LOCAL(__primary_switch)
#ifdef CONFIG_RANDOMIZE_BASE
	mov	x19, x0				// 保留新的SCTLR_EL1值
	mrs	x20, sctlr_el1			// 保留旧的SCTLR EL1值
#endif

	adrp	x1, init_pg_dir		//获取init_pg_dir的页表基地址
	bl	__enable_mmu			//开启mmu
#ifdef CONFIG_RELOCATABLE
#ifdef CONFIG_RELR
	mov	x24, #0				// no RELR displacement yet
#endif
	bl	__relocate_kernel
#ifdef CONFIG_RANDOMIZE_BASE	//我们没开，不看
	ldr	x8, =__primary_switched	//把__primary_switched的内容放入x8
	adrp	x0, __PHYS_OFFSET	//获取内核代码段的页表基地址
	blr	x8	//跳转到__primary_switched运行，返回的时候返回下一个指令

	/*
	 * If we return here, we have a KASLR displacement in x23 which we need
	 * to take into account by discarding the current kernel mapping and
	 * creating a new one.
	 */
	pre_disable_mmu_workaround
	msr	sctlr_el1, x20			// disable the MMU
	isb
	bl	__create_page_tables		// recreate kernel mapping

	tlbi	vmalle1				// Remove any stale TLB entries
	dsb	nsh
	isb

	msr	sctlr_el1, x19			// re-enable the MMU
	isb
	ic	iallu				// flush instructions fetched
	dsb	nsh				// via old mapping
	isb

	bl	__relocate_kernel
#endif
#endif
	ldr	x8, =__primary_switched	//把__primary_switched的内容放入x8
	adrp	x0, __PHYS_OFFSET	//获取内核代码段的页表基地址
	br	x8						//跳转到__primary_switched，并且不返回
SYM_FUNC_END(__primary_switch)
