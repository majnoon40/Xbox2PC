/* Minimal x64 IMAGE_TLS_DIRECTORY64 for the one __declspec(thread) variable. */
.section .rdata$T,"dr"
.p2align 3
.globl _tls_used
_tls_used:
    .quad tls_word
    .quad tls_word+4
    .quad _tls_index
    .quad 0
    .long 0
    .long 0
