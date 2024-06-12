#ifndef UTIL
#define UTIL

#include <unicorn/unicorn.h>
#include "DataType.h"

unsigned long long ReadBinaryFile(unsigned char** ppCODE, int* pCodeLength);
void PrintResult(uc_engine* pUC);

#endif