# slab allocator

​	The slab allocator is a "heap" allocator in Linux kernel. It works just like the glic ptmalloc allocator, servicing requests for small  piece of memory, yet has a different design and implementation.

> ​	There is actually no heap in kernel space, for there is no complete execution path in kernel space. Besides kernel codes, kernel memory is full of structs and are accessed by all kinds of pointers.



## from highest level

​	The record for an allocation of slab is arranged in three levels:

- cache
- slab
- allocation record



​	*cache* is an abstract layer 