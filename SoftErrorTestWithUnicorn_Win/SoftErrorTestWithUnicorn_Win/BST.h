#ifndef BST
#define BST

// binary search tree.

typedef struct _bstNode {
	uint64_t Key;
	unsigned int Value;
	unsigned int Height;
	struct _bstNode* pLeft;
	struct _bstNode* pRight;
} BstNode;
typedef struct _listNode {
	BstNode* pKey;
	struct _listNode* pPrev;
	struct _listNode* pNext;
} ListNode;

typedef struct _bst {
	BstNode* pTree;
	ListNode* pList;
} BSTree;

void InitializeTree(BSTree** ppBST);
void Add(BSTree* pBST, BstNode** ppNode);
BstNode* Get(BSTree* pBST, uint64_t key);
void ClearTree(BSTree** ppBST);

#endif