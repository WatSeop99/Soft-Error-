#include <stdio.h>
#include <errno.h>
#include "Util.h"

unsigned long long ReadBinaryFile(unsigned char** ppCODE, int* pCodeLength)
{
	FILE* pFile = NULL;
	unsigned char* pARM32_CODE = NULL;
	unsigned long long fileSize = 0;
	int codeLength = 0;
	const int CODE_OFFSET = 0x1000;

	fopen_s(&pFile, "./Math_Compiled", "rb");
	if (pFile == NULL)
	{
		printf("Failed to open file with %d.\n", errno);
		return -1;
	}

	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	pARM32_CODE = (unsigned char*)malloc(fileSize);
	if (!pARM32_CODE)
	{
		printf("Failed to allocate data memory.\n");
		return -1;
	}
	memset(pARM32_CODE, 0, fileSize);

	fseek(pFile, CODE_OFFSET, SEEK_SET);

	while (!feof(pFile))
	{
		fread(&pARM32_CODE[codeLength], sizeof(unsigned char), 1, pFile);
		++codeLength;
	}

	fclose(pFile);
	*ppCODE = pARM32_CODE;
	*pCodeLength = codeLength;

	return fileSize;
}

void PrintResult(uc_engine* pUC)
{
	float floatResult = 0.0f;
	Vector2 vec2Result = { 0.0f, };
	Vector3 vec3Result = { 0.0f, };
	Vector4 vec4Result = { 0.0f, };
	Matrix matResult = { 0.0f, };

	// print global variable in memory.
	uc_mem_read(pUC, 0xdd0c, (void*)(&floatResult), sizeof(float));
	uc_mem_read(pUC, 0xdd10, (void*)(&vec2Result), sizeof(Vector2));
	uc_mem_read(pUC, 0xdd18, (void*)(&vec3Result), sizeof(Vector3));
	uc_mem_read(pUC, 0xdd24, (void*)(&vec4Result), sizeof(Vector4));
	uc_mem_read(pUC, 0xdd34, (void*)(&matResult), sizeof(Matrix));

	printf("Print test result.\n");
	printf("float result: %f\n", floatResult);
	printf("vector2 result: { %f, %f }\n", vec2Result.X, vec2Result.Y);
	printf("vector3 reuslt: { %f, %f, %f }\n", vec3Result.X, vec3Result.Y, vec3Result.Z);
	printf("vector4 result: { %f, %f, %f, %f }\n", vec4Result.X, vec4Result.Y, vec4Result.Z, vec4Result.W);
	printf("matrix result: \n{ %f, %f, %f, %f,\n %f, %f, %f, %f, \n %f, %f, %f, %f,\n %f, %f, %f, %f }\n",
		   matResult._11, matResult._12, matResult._13, matResult._14,
		   matResult._21, matResult._22, matResult._23, matResult._24,
		   matResult._31, matResult._32, matResult._33, matResult._34,
		   matResult._41, matResult._42, matResult._43, matResult._44);
}