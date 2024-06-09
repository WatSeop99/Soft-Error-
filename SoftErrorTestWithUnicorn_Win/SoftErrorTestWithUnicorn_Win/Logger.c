#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
# include "Logger.h"

#ifdef TEST
// trees for error data in failed emulation.
BSTree* g_InstructionTree = NULL;
BSTree* g_RegisterTree = NULL;
BSTree* g_StackTree = NULL;

// trees for total error data in failed emulation.
BSTree* g_TotalInstructionTree = NULL;
BSTree* g_TotalRegisterTree = NULL;
BSTree* g_TotalStackTree = NULL;


int InitializeTestEnv()
{
	InitializeTree(&g_InstructionTree);
	InitializeTree(&g_RegisterTree);
	InitializeTree(&g_StackTree);

	InitializeTree(&g_TotalInstructionTree);
	InitializeTree(&g_TotalRegisterTree);
	InitializeTree(&g_TotalStackTree);

	return 0;
}

void StoreTestResults()
{
	FILE* pFile = NULL;
	ListNode* pHead = NULL;

	fopen_s(&pFile, "./TestOutput.txt", "w");
	if (pFile == NULL)
	{
		printf("Failed to open file with %d.\n", errno);
		return -1;
	}

	fprintf_s(pFile, "TextCodeAddress  Count\n");
	pHead = g_TotalInstructionTree->pList;
	while (pHead)
	{
		// {instruction address, flip count}
		fprintf_s(pFile, "%x  %d\n", pHead->pKey->Key, pHead->pKey->Value);
		pHead = pHead->pPrev;
	}
	fprintf_s(pFile, "\n");

	fprintf_s(pFile, "RegisterNo  Count\n");
	pHead = g_TotalRegisterTree->pList;
	while (pHead)
	{
		// {register, flip count}
		fprintf_s(pFile, "%d  %d\n", pHead->pKey->Key, pHead->pKey->Value);
		pHead = pHead->pPrev;
	}
	fprintf_s(pFile, "\n");

	fprintf_s(pFile, "StackAddress  Count\n");
	pHead = g_TotalStackTree->pList;
	while (pHead)
	{
		// {stack address, flip count}
		fprintf_s(pFile, "%x  %d\n", pHead->pKey->Key, pHead->pKey->Value);
		pHead = pHead->pPrev;
	}
	fprintf_s(pFile, "\n");

	fclose(pFile);
}

void ClearTestEnv()
{
	ClearTree(&g_InstructionTree);
	ClearTree(&g_RegisterTree);
	ClearTree(&g_StackTree);

	free(g_InstructionTree);
	g_InstructionTree = NULL;

	free(g_RegisterTree);
	g_RegisterTree = NULL;

	free(g_StackTree);
	g_StackTree = NULL;

	ClearTree(&g_TotalInstructionTree);
	ClearTree(&g_TotalRegisterTree);
	ClearTree(&g_TotalStackTree);

	free(g_TotalInstructionTree);
	g_TotalInstructionTree = NULL;

	free(g_TotalRegisterTree);
	g_TotalRegisterTree = NULL;

	free(g_TotalStackTree);
	g_TotalStackTree = NULL;
}

#endif
