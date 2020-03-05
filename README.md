# snapshot-lkm

A kernel module that creates a `snapshot()` syscall for fast fuzzing. Developed off of kernel `5.4.23`, but since this is a LKM hopefully version doesn't matter (too much :P).

Idea from [AFL++ ideas page](https://github.com/vanhauser-thc/AFLplusplus/blob/master/docs/ideas.md).

For original implementation, see [https://github.com/sslab-gatech/perf-fuzz](https://github.com/sslab-gatech/perf-fuzz).
