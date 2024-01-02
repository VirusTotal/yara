#ifndef YR_ELF_UTILS_H
#define YR_ELF_UTILS_H

#include <yara/elf.h>

typedef struct _ELF_SYMBOL
{
  char *name;
  int value;
  int size;
  int type;
  int bind;
  int shndx;
  int visibility;

  struct _ELF_SYMBOL *next; // Next symbol in the list
} ELF_SYMBOL;

// Linked list of symbols
typedef struct _ELF_SYMBOL_LIST
{
  int count;
  ELF_SYMBOL *symbols;
} ELF_SYMBOL_LIST;

typedef struct _ELF
{
  ELF_SYMBOL_LIST *symtab;
  ELF_SYMBOL_LIST *dynsym;
  char *telfhash;
  char *import_hash;
} ELF;

#endif //YR_ELF_UTILS_H
