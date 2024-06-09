#include <stdlib.h>
#include <stdint.h>
#include "BST.h"

// private function for bst.
static unsigned int Max(const unsigned int, const unsigned int);
static void InsertNode(BstNode** ppTree, BstNode* pNewNode);
static BstNode* Balance(BstNode* pTree);
static BstNode* SearchNode(BstNode* pCurNode, uint64_t key);
static int GetDifference(BstNode* pTree);
static void SetHeight(BstNode* pNode);
static int GetHeight(BstNode* pTree);
static BstNode* RotateLL(BstNode* pTree);
static BstNode* RotateRR(BstNode* pTree);
static BstNode* RotateLR(BstNode* pTree);
static BstNode* RotateRL(BstNode* pTree);
static void DeleteTree(BstNode** ppTree);


void InitializeTree(BSTree** ppBST)
{
	*ppBST = (BSTree*)malloc(sizeof(BSTree));
	(*ppBST)->pTree = NULL;
	(*ppBST)->pList = NULL;
}

void Add(BSTree* pBST, BstNode** ppNode)
{
	BstNode* findNode = Get(pBST, (*ppNode)->Key);
	if (!findNode)
	{
		InsertNode(&(pBST->pTree), *ppNode);
		pBST->pTree = Balance(pBST->pTree);


		ListNode* pNewListNode = (ListNode*)malloc(sizeof(ListNode));
		pNewListNode->pKey = *ppNode;
		pNewListNode->pNext = NULL;
		pNewListNode->pPrev = NULL;
		if (pBST->pList == NULL)
		{
			pBST->pList = pNewListNode;
		}
		else
		{
			pNewListNode->pPrev = pBST->pList;
			pBST->pList->pNext = pNewListNode;
			pBST->pList = pNewListNode;
		}
	}
	else
	{
		++(findNode->Value);
		free(*ppNode);
		*ppNode = NULL;
	}
}

BstNode* Get(BSTree* pBST, uint64_t key)
{
	if (pBST == NULL || pBST->pTree == NULL)
	{
		return NULL;
	}

	return SearchNode(pBST->pTree, key);
}

void ClearTree(BSTree** ppBST)
{
	if (!(*ppBST))
	{
		return;
	}

	DeleteTree(&((*ppBST)->pTree));

	while ((*ppBST)->pList)
	{
		ListNode* pTemp = (*ppBST)->pList;
		(*ppBST)->pList = (*ppBST)->pList->pPrev;
		free(pTemp);
		pTemp = NULL;
	}
}


////////// private function //////////
unsigned int Max(const unsigned int A, const unsigned int B)
{
	return (A > B ? A : B);
}

void InsertNode(BstNode** ppTree, BstNode* pNewNode)
{
	if (!(*ppTree))
	{
		*ppTree = pNewNode;
		return;
	}

	if (pNewNode->Key < (*ppTree)->Key)
	{
		InsertNode(&((*ppTree)->pLeft), pNewNode);
		(*ppTree)->pLeft = Balance((*ppTree)->pLeft);
	}
	else if (pNewNode->Key > (*ppTree)->Key)
	{
		InsertNode(&((*ppTree)->pRight), pNewNode);
		(*ppTree)->pRight = Balance((*ppTree)->pRight);
	}
}

BstNode* Balance(BstNode* pTree)
{
	int diff = GetDifference(pTree);
	if (diff >= 2)
	{
		if (GetDifference(pTree->pLeft) >= 1)
		{
			pTree = RotateLL(pTree);
		}
		else
		{
			pTree = RotateLR(pTree);
		}
	}
	else if (diff <= -2)
	{
		if (GetDifference(pTree->pRight) <= -1)
		{
			pTree = RotateRR(pTree);
		}
		else
		{
			pTree = RotateRL(pTree);
		}
	}

	SetHeight(pTree);
	return pTree;
}

BstNode* SearchNode(BstNode* pCurNode, uint64_t key)
{
	if (!pCurNode)
	{
		return NULL;
	}

	if (key < pCurNode->Key)
	{
		return SearchNode(pCurNode->pLeft, key);
	}
	else if (key > pCurNode->Key)
	{
		return SearchNode(pCurNode->pRight, key);
	}
	else
	{
		return pCurNode;
	}
}

int GetDifference(BstNode* pTree)
{
	if (!pTree)
	{
		return 0;
	}

	return GetHeight(pTree->pLeft) - GetHeight(pTree->pRight);
}

void SetHeight(BstNode* pNode)
{
	pNode->Height = Max(GetHeight(pNode->pLeft), GetHeight(pNode->pRight));
}

int GetHeight(BstNode* pTree)
{
	if (!pTree)
	{
		return 0;
	}
	return pTree->Height;
}

BstNode* RotateLL(BstNode* pTree)
{
	BstNode* pLeftChild = pTree->pLeft;
	pTree->pLeft = pLeftChild->pRight;
	pLeftChild->pRight = pTree;

	SetHeight(pTree);
	return pLeftChild;
}

BstNode* RotateRR(BstNode* pTree)
{
	BstNode* pRightChild = pTree->pRight;
	pTree->pRight = pRightChild->pLeft;
	pRightChild->pLeft = pTree;

	SetHeight(pTree);
	return pRightChild;
}

BstNode* RotateLR(BstNode* pTree)
{
	BstNode* pLeftChild = pTree->pLeft;
	pTree->pLeft = RotateRR(pLeftChild);

	SetHeight(pTree->pLeft);
	return RotateLL(pTree);
}

BstNode* RotateRL(BstNode* pTree)
{
	BstNode* pRightChild = pTree->pRight;
	pTree->pRight = RotateLL(pRightChild);

	SetHeight(pTree->pRight);
	return RotateRR(pTree);
}

void DeleteTree(BstNode** ppTree)
{
	if (*ppTree)
	{
		DeleteTree(&((*ppTree)->pLeft));
		DeleteTree(&((*ppTree)->pRight));
		free(*ppTree);
		*ppTree = NULL;
	}
}
