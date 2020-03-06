#include <linux/linkage.h>
ENTRY(wp_page_hook_trampoline)

push %rdi
push %rsi
push %rdx
push %rcx
push %r8
push %r9

call wp_page_hook

pop %r9
pop %r8
pop %rcx
pop %rdx
pop %rsi
pop %rdi

test %rax, %rax

jz out

# non-zero; skip over the `call wp_page_hook_trampoline` ret address to ret to the hooked functions caller

add 8, %rsp

out:

ret

END(wp_page_hook_trampoline)


ENTRY(detour_placeholder)
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
END(detour_placeholder)
