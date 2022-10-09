# pt-dump-lib

`pt-dump-lib` is a library for parsing page tables and examining the system address space of a given target.

Among the supported features include:

* Parsing a page table at a given address for X86-64, X86-32, Aarch64 (WIP), RV64 (WIP)
* Memory searching based on page table contents
* Filtering pages based on page attributes

The project was primarily started to improve performance, testability, correctness of the https://github.com/martinradev/gdb-pt-dump project.
