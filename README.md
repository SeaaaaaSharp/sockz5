## SOCKS5 proxy built using Zig and Linux's io_uring (WIP).

Designed with these ideas in mind:

* Minimizing syscall overhead.

* Zero runtime memory allocation: All required memory is computed and allocated upfront and reused thereafter.

* Bounded connections: Hard limit on the amount of concurrenct connections and sessions to avoid unbounded allocations.

* Defensive programming: Exhaustive asserts everywhere to catch any invariant violation.

## Prerequisites

* **OS:** Linux kernel 7.1+.
* **Compiler:** Zig 0.16.0 compiler.
