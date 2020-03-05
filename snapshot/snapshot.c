#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/kallsyms.h>  // kallsyms_lookup_name
#include <linux/list.h>      // hlist

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kallsyms");
MODULE_DESCRIPTION("Adds a snapshot() syscall to make fuzzing faster");
MODULE_VERSION("1.0.0");

// Currently overwrite SYS_tuxcall because why not
#define HIJACKED_SYSCALL __NR_tuxcall

typedef int (*syscall_func_t)(struct pt_regs*);

// The original syscall handler that we removed for sys_snapshot(), most likely __x64_sys_ni_syscall
syscall_func_t orig_sct_snapshot_entry = NULL;

// The original syscall handler that we removed to override exit_group()
syscall_func_t orig_sct_exit_group = NULL;

struct files_struct_meta {
    unsigned long *snapshot_open_fds;
};

struct mm_snapshot {
    unsigned int status;
    // ...
};

// TODO: non-x86 architectures sys_call_table entries don't take pt_regs,
// they take normal args
// https://grok.osiris.cyber.nyu.edu/xref/linux/include/linux/syscalls.h?r=83fa805b#235
// but x86 is (of course) different, taking a pt_regs, then passing extracted
// values to the actual __do_sys*
// https://grok.osiris.cyber.nyu.edu/xref/linux/arch/x86/include/asm/syscall_wrapper.h?r=6e484764#161

asmlinkage int sys_snapshot(struct pt_regs *regs)
{
    return 1337;
}

asmlinkage int sys_exit_group(struct pt_regs *regs)
{
    return orig_sct_exit_group(regs);
}

static int __init mod_init(void)
{
    void **sys_call_table = (void**)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        printk(KERN_ERR "Unable to locate sys_call_table");
        return 1;
    }

    write_cr0(read_cr0() & (~(1 << 16)));
    orig_sct_snapshot_entry = sys_call_table[HIJACKED_SYSCALL];
    orig_sct_exit_group = sys_call_table[__NR_exit_group];
    sys_call_table[HIJACKED_SYSCALL] = &sys_snapshot;
    sys_call_table[__NR_exit_group] = &sys_exit_group;
    write_cr0(read_cr0() | (1 << 16));

    return 0;
}

static void __exit mod_exit(void) {
    void **sys_call_table = (void**)kallsyms_lookup_name("sys_call_table");
    write_cr0(read_cr0() & (~(1 << 16)));
    sys_call_table[HIJACKED_SYSCALL] = orig_sct_snapshot_entry;
    sys_call_table[__NR_exit_group] = orig_sct_exit_group;
    write_cr0(read_cr0() | (1 << 16));
}

module_init(mod_init);
module_exit(mod_exit);
