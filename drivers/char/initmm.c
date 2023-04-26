#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/cache.h>
#include <linux/screen_info.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/root_dev.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/of_fdt.h>
#include <linux/efi.h>
#include <linux/psci.h>
#include <linux/sched/task.h>
#include <linux/mm.h>

#include <asm/acpi.h>
#include <asm/fixmap.h>
#include <asm/cpu.h>


#include <asm/elf.h>
#include <asm/cpufeature.h>

#include <asm/kasan.h>
#include <asm/numa.h>
#include <asm/sections.h>
#include <asm/setup.h>

#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/traps.h>
#include <asm/efi.h>
#include <asm/xen/hypervisor.h>
#include <asm/mmu_context.h>


int init_module(void)
{


	printk(KERN_INFO "init_mm.mmap_base = 0x%llx\n",init_mm.mmap_base);
	printk(KERN_INFO "init_mm.task_size = 0x%llx\n",init_mm.task_size);
	printk(KERN_INFO "init_mm.highest_vm_end = 0x%llx\n",init_mm.highest_vm_end);
	printk(KERN_INFO "init_mm.pgtables_bytes = 0x%llx\n",init_mm.pgtables_bytes);
	printk(KERN_INFO "init_mm.start_code = 0x%llx\n",init_mm.start_code);
	printk(KERN_INFO "init_mm.end_code = 0x%llx\n",init_mm.end_code);
	printk(KERN_INFO "init_mm.start_data = 0x%llx\n",init_mm.start_data);
	printk(KERN_INFO "init_mm.end_data = 0x%llx\n",init_mm.end_data);
	printk(KERN_INFO "init_mm.start_brk = 0x%llx\n",init_mm.start_brk);
	printk(KERN_INFO "init_mm.brk = 0x%llx\n",init_mm.brk);
	printk(KERN_INFO "init_mm.start_stack = 0x%llx\n",init_mm.start_stack);
	printk(KERN_INFO "init_mm.arg_start = 0x%llx\n",init_mm.arg_start);
	printk(KERN_INFO "init_mm.arg_end = 0x%llx\n",init_mm.arg_end);
	printk(KERN_INFO "init_mm.env_start = 0x%llx\n",init_mm.env_start);
	printk(KERN_INFO "init_mm.env_end = 0x%llx\n",init_mm.env_end);
  
  
  return 0;
}

void cleanup_module(void)
{
  printk(KERN_INFO "Goodbye world!\n");
}


