#ifndef YR_ELF_UTILS_H
#define YR_ELF_UTILS_H

#include <yara/elf.h>

//
// Symbols are stored in a linked list.
//
typedef struct _ELF_SYMBOL
{
  char *name;
  int value;
  int size;
  int type;
  int bind;
  int shndx;

  struct _ELF_SYMBOL *next;
} ELF_SYMBOL;

typedef struct _ELF_SYMBOL_TABLE
{
  int count;
  ELF_SYMBOL *symbols;
} ELF_SYMBOL_TABLE;

typedef struct _ELF
{
  ELF_SYMBOL_TABLE *symtab;
} ELF;

#endif //YR_ELF_UTILS_H
