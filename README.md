# snapshot-lkm

A kernel module that creates a `snapshot()` syscall for fast fuzzing.
Developed off of kernel `5.4.23`, but since this is a LKM hopefully version doesn't matter (too much).

Idea from [AFL++ ideas page](https://github.com/vanhauser-thc/AFLplusplus/blob/master/docs/ideas.md).

For original implementation (as a kernel fork/patch), see [https://github.com/sslab-gatech/perf-fuzz](https://github.com/sslab-gatech/perf-fuzz).

## How it works

* Overwrites `sys_tuxcall` (unused) syscall table entry for the "new" snapshot syscall
* Overwrites syscall table to intercept `sys_exit_group` (and maybe restore state)
* Has a hooking library to intercept other functions
    * [hook.c](./snapshot/hook.c)
    * The handler callback can return non-zero to have the original function not be run at all
