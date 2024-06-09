#ifndef LOGGER
#define LOGGER

// #define TEST
#include "BST.h"

typedef struct _registerInfo {
	unsigned int LastRegisterNo;
	unsigned int Mask;
	unsigned int Value;
} RegisterInfo;

typedef struct _stackInfo {
	uint64_t Address;
	unsigned int Value;
	unsigned int Mask;
} StackInfo;

typedef struct _instructionInfo {
	unsigned long long InstructionValue;
	// uint64_t PCValue;
	uint64_t Address;
	unsigned int Mask;
} InstructionInfo;

#ifdef TEST
extern BSTree* g_InstructionTree;
extern BSTree* g_RegisterTree;
extern BSTree* g_StackTree;

extern BSTree* g_TotalInstructionTree;
extern BSTree* g_TotalRegisterTree;
extern BSTree* g_TotalStackTree;

int InitializeTestEnv();
void StoreTestResults();
void ClearTestEnv();
#endif

#endif
