bits 64
section .text
global _start
_start:
mov rax, 1
mov rbx, 0
int 0x80
