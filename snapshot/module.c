#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/kallsyms.h>  // kallsyms_lookup_name

#include "associated_data.h"  // mm associated data
#include "hook.h"             // function hooking
#include "snapshot.h"         // main implementation

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kallsyms");
MODULE_DESCRIPTION("Adds a snapshot() syscall to make fuzzing faster");
MODULE_VERSION("1.0.0");

// Currently overwrite SYS_tuxcall because why not
#define __NR_snapshot __NR_tuxcall


typedef int (*syscall_handler_t)(struct pt_regs*);

// The original syscall handler that we removed for sys_snapshot(), most likely __x64_sys_ni_syscall
syscall_handler_t orig_sct_snapshot_entry = NULL;

// The original syscall handler that we removed to override exit_group()
syscall_handler_t orig_sct_exit_group = NULL;


// TODO: non-x86 architectures syscall_table entries don't take pt_regs,
// they take normal args
// https://grok.osiris.cyber.nyu.edu/xref/linux/include/linux/syscalls.h?r=83fa805b#235
// but x86 is (of course) different, taking a pt_regs, then passing extracted
// values to the actual __do_sys*
// https://grok.osiris.cyber.nyu.edu/xref/linux/arch/x86/include/asm/syscall_wrapper.h?r=6e484764#161

asmlinkage int sys_snapshot(struct pt_regs *regs)
{
    unsigned long option = regs->di;
    unsigned long arg = regs->si;

    switch (option) {
        case SNAPSHOT_START:
            make_snapshot(arg);
            return 0;
        case SNAPSHOT_END:
            recover_snapshot(arg);
            return 0;
    }

    return -EINVAL;
}

asmlinkage int sys_exit_group(struct pt_regs *regs)
{
    struct mm_data *data = get_mm_data(current->mm);
    if (data && have_snapshot(data)) {
        snapshot_cleanup(current);
        return 0;
    }

    if (data && had_snapshot(data)) {
        clean_snapshot();
    }

    return orig_sct_exit_group(regs);
}

bool wp_page_hook(struct vm_fault *vmf)
{
    printk(KERN_INFO "wp_page_hook: addr=%llx", vmf->address);
    return 0; // let the normal function run
}

// hook.S
asmlinkage void wp_page_hook_trampoline(void);

static void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val));
}

static void **get_syscall_table(void)
{
    void **syscall_table;
    
    syscall_table = kallsyms_lookup_name("sys_call_table");

    if (syscall_table) {
        return syscall_table;
    }
    
    int i;
    unsigned long long s0 = kallsyms_lookup_name("__x64_sys_read");
    unsigned long long s1 = kallsyms_lookup_name("__x64_sys_write");

    unsigned long long *data = (unsigned long long*)((uint64_t)kallsyms_lookup_name("_etext") & ~0x7);
    for (i = 0; (unsigned long long)(&data[i]) < ULLONG_MAX; i++) {
        unsigned long long d;
        // use probe_kernel_read so we don't fault
        if (probe_kernel_read(&d, &data[i], sizeof(d))) {
            continue;
        }

        if (d == s0 && data[i+1] == s1) {
            syscall_table = (void**)(&data[i]);
            break;
        }
    }

    return syscall_table;
}

static void unpatch_syscall_table(void)
{
    void **syscall_table = get_syscall_table();
    _write_cr0(read_cr0() & (~(1 << 16)));
    syscall_table[__NR_snapshot] = orig_sct_snapshot_entry;
    syscall_table[__NR_exit_group] = orig_sct_exit_group;
    _write_cr0(read_cr0() | (1 << 16));
}

static int __init mod_init(void)
{
    // helpers
    if (!init_hooking()) {
        printk(KERN_ERR "Unable to initialize hooking subsystem");
        return -ENOENT;
    }

    // syscall_table overwrites
    void **syscall_table = get_syscall_table();
    if (!syscall_table) {
        printk(KERN_ERR "Unable to locate syscall_table");
        return -ENOENT;
    }

    _write_cr0(read_cr0() & (~(1 << 16)));
    orig_sct_snapshot_entry = syscall_table[__NR_snapshot];
    orig_sct_exit_group = syscall_table[__NR_exit_group];
    syscall_table[__NR_snapshot] = &sys_snapshot;
    syscall_table[__NR_exit_group] = &sys_exit_group;
    _write_cr0(read_cr0() | (1 << 16));

    // func hooks
    if (!try_hook("do_wp_page", &wp_page_hook_trampoline)) {
        printk(KERN_ERR "Unable to hook do_wp_page");
        unpatch_syscall_table();
        return -ENOENT;
    }

    // initialize snapshot non-exported funcs
    return snapshot_initialize_k_funcs();
}

static void __exit mod_exit(void) {

    unhook("do_wp_page");
    unpatch_syscall_table();
}

module_init(mod_init);
module_exit(mod_exit);
