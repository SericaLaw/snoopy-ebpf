# Snoopy-eBPF: Catching Program Executions with eBPF

[companion blog post](https://www.iserica.com/posts/snoopy-ebpf-implementation/)

## Example

Run snoopy and type `ls` in another terminal, you will get the process's tid and name that executes the `ls` program, as well as the arguments passed to the program.

![-16374148560321](https://cdn.jsdelivr.net/gh/SericaLaw/images@master/20211120/-16374148560321.png)