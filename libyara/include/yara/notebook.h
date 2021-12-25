//
// Created by Victor Manuel Alvarez on 3/4/20.
//

#ifndef YR_NOTEBOOK_H
#define YR_NOTEBOOK_H

#include <stdlib.h>

typedef struct YR_NOTEBOOK YR_NOTEBOOK;

int yr_notebook_create(size_t page_size, YR_NOTEBOOK** pool);

int yr_notebook_destroy(YR_NOTEBOOK* pool);

void* yr_notebook_alloc(YR_NOTEBOOK* notebook, size_t size);

#endif  // YR_NOTEBOOK_H
