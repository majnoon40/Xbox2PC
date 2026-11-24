// Minimal SysV-to-Windows-x64 leaf-call thunk.
.text
.globl xbox2pc_native_call0
.type xbox2pc_native_call0,@function
xbox2pc_native_call0:
    pushq %rbp
    movq %rsp, %rbp
    subq $32, %rsp
    call *%rdi
    movq %rbp, %rsp
    popq %rbp
    ret
.size xbox2pc_native_call0, .-xbox2pc_native_call0
.section .note.GNU-stack,"",@progbits
