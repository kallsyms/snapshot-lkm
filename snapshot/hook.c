#include <linux/list.h>  // list_for_each_entry
#include <linux/slab.h>  // kmalloc, GFP_*
#include <asm/insn.h>

#include <linux/kallsyms.h>  // kallsyms_lookup_name

struct hook {
    void *func;
    unsigned char *detour;
    size_t detour_len;
    struct list_head l;
};

LIST_HEAD(hooks);


static void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val));
}

const char nop[5] = {0x0f, 0x1f, 0x44, 0x00, 0x00};

void (*k_insn_init)(
    struct insn *insn, const void *kaddr,
    int buf_len, int x86_64);

void (*k_insn_get_length)(struct insn *insn);

bool init_hooking(void)
{
    k_insn_init = kallsyms_lookup_name("insn_init");
    k_insn_get_length = kallsyms_lookup_name("insn_get_length");

    return k_insn_init && k_insn_get_length;
}


// hooks.S
asmlinkage void detour_placeholder(void);

off_t detour_used = 0;

bool try_hook(const char *func_name, void *handler)
{
    unsigned char *func = kallsyms_lookup_name(func_name);
    if (!func) {
        printk(KERN_WARNING "Could not find symbol %s for hooking", func_name);
        return false;
    }

    struct hook *hook = kmalloc(sizeof(struct hook), GFP_KERNEL | __GFP_ZERO);
    INIT_LIST_HEAD(&hook->l);
    hook->func = func;

    if (memcmp(func, nop, sizeof(nop))) {
        // don't have a handy call at the top of func, need to detour
        // N.B. this doesn't do any checks on what its ripping out which could cause issues

        int len = 0;
        struct insn insn;
        while (len < 5) {
            k_insn_init(&insn, func + len, MAX_INSN_SIZE, 1);
            k_insn_get_length(&insn);
            len += insn.length;
        }

        // get a chunk of our detour_placeholder function
        unsigned char *detour = ((unsigned char*)&detour_placeholder) + detour_used;
        detour_used += 5 + len + 5;

        _write_cr0(read_cr0() & (~(1 << 16)));

        // call our handler
        int32_t call_offset = ((unsigned char *)handler) - (detour + 5);
        *detour = 0xe8;
        *(int32_t*)(detour + 1) = call_offset;

        // copy lifted instructions
        memcpy(detour + 5, func, len);

        // and jump to the rest of the function after
        int32_t jmp_offset = (func + len) - (detour + 5 + len + 5);
        *(detour + 5 + len) = 0xe9;
        *(int32_t*)(detour + 5 + len + 1) = jmp_offset;

        // now that the detour is in place, overwrite the func insns we copied
        // with a jump to the detour
        jmp_offset = detour - (func + 5);

        *func = 0xe9;
        *(int32_t*)(func + 1) = jmp_offset;

        _write_cr0(read_cr0() | (1 << 16));

        hook->detour = detour;
        hook->detour_len = 5 + len + 5;
    } else {
        // have a nice 5 byte call we can overwrite
        int32_t call_offset = ((unsigned char *)handler) - (func + 5);

        _write_cr0(read_cr0() & (~(1 << 16)));

        *func = 0xe8;
        *(int32_t*)(func + 1) = call_offset;

        _write_cr0(read_cr0() | (1 << 16));
    }

    list_add(&hook->l, &hooks);

    return true;
}

void unhook(const char *func_name)
{
    void *func = kallsyms_lookup_name(func_name);

    struct hook *hook = NULL;
    list_for_each_entry(hook, &hooks, l) {
        if (hook->func == func) {
            _write_cr0(read_cr0() & (~(1 << 16)));

            if (!hook->detour) {
                memcpy(func, nop, sizeof(nop));
            } else {
                memcpy(func, hook->detour + 5, hook->detour_len - 10);
            }

            _write_cr0(read_cr0() | (1 << 16));

            return;
        }
    }
}
