#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <time.h>
#include <Windows.h>
#include <unicorn/unicorn.h>

#define CAPSTONE_HAS_ARM
#include <capstone/capstone.h>

#include "DataType.h"
#include "Logger.h"
#include "Inspection.h"

typedef int Bool;
#define False 0
#define True 1

#define TEST 0 // Test Mode.

// Global variable.
csh g_CSHandle;
int g_DirtyCount = 0;
int g_FaultFlag = 0;
Bool g_bDirtyFlag = False;
float g_ErrorProbability = 0.0f;
int g_SuccessCount = 0;				// success count.
int g_FailEmulationCount = 0;		// fail type1 count.
int g_FailProducingResultCount = 0; // fail type2 count.

// Global variable for logging.
RegisterInfo g_RegisterInfo = { 0, };
StackInfo g_StackInfo = { 0, };
InstructionInfo g_InstructionInfo = { 0, };


unsigned long long FileRead(unsigned char** ppCODE, int* pCodeLength);
void PrintResult(uc_engine* pUC);

void HookInstruction(uc_engine* pUC, uint64_t address, uint32_t size, void* pUserData)
{
	unsigned char data[9] = { 0, };
	cs_insn* pInsn = NULL;
	size_t count = 0;
	double num = 0.0f;
	unsigned int mask = 0;
	unsigned int pcValue = 0;
	unsigned int regValue = 0;
	unsigned int spRegValue = 0;
	unsigned int value = 0;

#if !TEST
	// print current instruction.
	uc_mem_read(pUC, address, data, size);
	count = cs_disasm(g_CSHandle, data, size, address, 0, &pInsn);
	if (count > 0)
	{
		for (size_t i = 0; i < count; ++i)
		{
			printf(">>>>Instruction at 0x%lx: %s %s\n", address, pInsn[i].mnemonic, pInsn[i].op_str);
		}

		cs_free(pInsn, count);
	}
#endif


	// restore bit flip if dirty flag active.
	if (g_bDirtyFlag)
	{
#if !TEST
		printf("\nbit mask restore..\n");
#endif

		// restore PC.
		if (g_FaultFlag & Instruction)
		{
			uc_reg_write(pUC, UC_ARM_REG_PC, &(g_InstructionInfo.PCValue));
		}

		// restore stack area.
		if (g_FaultFlag & Stack)
		{
			uc_mem_write(pUC, g_StackInfo.Address + g_StackInfo.Offset, &(g_StackInfo.Value), sizeof(unsigned int));
		}

		// restore resgister(r0~r5).
		if (g_FaultFlag & Register)
		{
			switch (g_RegisterInfo.LastRegisterNo)
			{
				case 0:
					uc_reg_write(pUC, ARM_REG_R0, &(g_RegisterInfo.Value));
					break;

				case 1:
					uc_reg_write(pUC, ARM_REG_R1, &(g_RegisterInfo.Value));
					break;

				case 2:
					uc_reg_write(pUC, ARM_REG_R2, &(g_RegisterInfo.Value));
					break;

				case 3:
					uc_reg_write(pUC, ARM_REG_R3, &(g_RegisterInfo.Value));
					break;

				case 4:
					uc_reg_write(pUC, ARM_REG_R4, &(g_RegisterInfo.Value));
					break;

				case 5:
					uc_reg_write(pUC, ARM_REG_R5, &(g_RegisterInfo.Value));
					break;

				default:
					break;
			}
		}
	}

	// determined if you want to try bit flip at this point in time.
	num = (double)rand() / RAND_MAX;
	if (num > g_ErrorProbability)
	{
		g_bDirtyFlag = False;
		return;
	}

	g_bDirtyFlag = True;
#if !TEST
	printf("\nbit masking Info...\n");
#endif

	// flip bit according to the option.
	if (g_FaultFlag & Instruction)
	{
#if !TEST
		printf("--PC Bit Masking Info--\n");
#endif
		// create mask value.
		mask = rand() % 32;
		g_InstructionInfo.Mask = mask;

		// flip PC value using mask.
		uc_reg_read(pUC, UC_ARM_REG_PC, &pcValue);
		g_InstructionInfo.PCValue = pcValue;
		pcValue ^= mask;
		uc_reg_write(pUC, UC_ARM_REG_PC, &pcValue);

#if !TEST
		printf("original pc: 0x%x\n", g_InstructionInfo.PCValue);
		printf("mask: 0x%x\n", mask);
		printf("bit flip pc: 0x%x\n", pcValue);
#endif

	}
	if (g_FaultFlag & Register)
	{
#if !TEST
		printf("--Register Bit Masking Info--\n");
#endif

		int registerNum = 0;

		// select register(r0 ~ r5) and create mask value.
		registerNum = rand() % 6;
		mask = rand() % 32;
		g_RegisterInfo.LastRegisterNo = registerNum;
		g_RegisterInfo.Mask = mask;

		// flip register value using mask.
		switch (registerNum)
		{
			case 0:
				uc_reg_read(pUC, UC_ARM_REG_R0, &regValue);
				g_RegisterInfo.Value = regValue;
				regValue ^= mask;
				uc_reg_write(pUC, UC_ARM_REG_R0, &regValue);
				break;

			case 1:
				uc_reg_read(pUC, UC_ARM_REG_R1, &regValue);
				g_RegisterInfo.Value = regValue;
				regValue ^= mask;
				uc_reg_write(pUC, UC_ARM_REG_R1, &regValue);
				break;

			case 2:
				uc_reg_read(pUC, UC_ARM_REG_R2, &regValue);
				g_RegisterInfo.Value = regValue;
				regValue ^= mask;
				uc_reg_write(pUC, UC_ARM_REG_R2, &regValue);
				break;

			case 3:
				uc_reg_read(pUC, UC_ARM_REG_R3, &regValue);
				g_RegisterInfo.Value = regValue;
				regValue ^= mask;
				uc_reg_write(pUC, UC_ARM_REG_R3, &regValue);
				break;

			case 4:
				uc_reg_read(pUC, UC_ARM_REG_R4, &regValue);
				g_RegisterInfo.Value = regValue;
				regValue ^= mask;
				uc_reg_write(pUC, UC_ARM_REG_R4, &regValue);
				break;

			case 5:
				uc_reg_read(pUC, UC_ARM_REG_R5, &regValue);
				g_RegisterInfo.Value = regValue;
				regValue ^= mask;
				uc_reg_write(pUC, UC_ARM_REG_R5, &regValue);
				break;

			default:
				break;
		}

#if !TEST
		printf("chosen register: r%d\n", g_RegisterInfo.LastRegisterNo);
		printf("original register: 0x%x\n", g_RegisterInfo.Value);
		printf("mask: 0x%x\n", g_RegisterInfo.Mask);
		printf("bit flip register: 0x%x\n", regValue);
#endif
	}
	if (g_FaultFlag & Stack)
	{
#if !TEST
		printf("--Stack Area Bit Masking Info--\n");
#endif

		const unsigned int START_SP_VALUE = 0x80000;
		unsigned int offset = 0;

		// create maks value.
		mask = rand() % 32;
		g_StackInfo.Mask = mask;

		uc_reg_read(pUC, UC_ARM_REG_SP, &spRegValue);
		g_StackInfo.Address = spRegValue;
		g_StackInfo.Offset = 0;

		// select the point of stack to bit flip.
		// point is calculated as (current sp address + offset).
		if (spRegValue != START_SP_VALUE)
		{
			offset = rand() % (START_SP_VALUE - spRegValue + 1); // create offset.
			g_StackInfo.Offset = offset;
		}

		// flip stack area value.
		uc_mem_read(pUC, spRegValue + offset, &value, sizeof(unsigned int));
		g_StackInfo.Value = value;
		value ^= mask;
		uc_mem_write(pUC, spRegValue + offset, &value, sizeof(unsigned int));

#if !TEST
		printf("original sp: 0x%x\n", g_StackInfo.Address);
		printf("address: 0x%x\n", g_StackInfo.Address + g_StackInfo.Offset);
		printf("mask: 0x%x\n", mask);
		printf("original value: 0x%x\n", g_StackInfo.Value);
		printf("bit flip value: 0x%x\n", value);
#endif
	}

#if !TEST
	printf("\n");
#endif
}

unsigned long long FileRead(unsigned char** ppCODE, int* pCodeLength)
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

void TestFunc(unsigned char* pARM32_CODE, unsigned long long fileSize, int codeLength)
{
	uc_engine* pUC = NULL;
	uc_hook traceInsn;
	uc_err err = UC_ERR_OK;
	
	// for elapsed time.
	LARGE_INTEGER startFrequency;
	LARGE_INTEGER prevCounter;
	LARGE_INTEGER curCounter;
	float elapsedTick = 0.0f;

	QueryPerformanceFrequency(&startFrequency);

	// data for emulation.
	const unsigned int CODE_START_ADDRESS = 0x8000;
	const unsigned int ENTRY_POINT_ADDRESS = 0x81dc;
	const unsigned int ENTRY_POINT_END_ADDRESS = 0x8268;
	const unsigned int MAIN_FUNC_ADDRESS = 0x828c;
	const unsigned int STACK_ADDRESS = 0x80000;
	int regValue = 0;

	printf("Emulate ARM code (ing)...\n");
	printf("[System] The emulating process will be continued.\n");

	// create Unicorn module.
	err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &pUC);
	if (err != UC_ERR_OK)
	{
		printf("Failed to open uc engine error with %u(%s).\n", err, uc_strerror(err));
		goto LB_ERROR_PROCESSING;
	}

	// allocate memory.
	uc_mem_map(pUC, 0, 4 * 1024 * 1024, UC_PROT_ALL);

	// write code and register(sp, fp) value.
	uc_mem_write(pUC, CODE_START_ADDRESS, pARM32_CODE, fileSize);
	uc_reg_write(pUC, UC_ARM_REG_SP, &STACK_ADDRESS);
	uc_reg_write(pUC, UC_ARM_REG_FP, &STACK_ADDRESS);

	// add hook function.
	uc_hook_add(pUC, &traceInsn, UC_HOOK_CODE, HookInstruction, NULL, CODE_START_ADDRESS, CODE_START_ADDRESS + codeLength);

	QueryPerformanceCounter(&prevCounter);

	// emulate the code for 10 seconds.
	// if duration goes over 10 sec, then emulation would fail.
	err = uc_emu_start(pUC, ENTRY_POINT_ADDRESS, ENTRY_POINT_END_ADDRESS, 10000000, 0);
	if (err != UC_ERR_OK)
	{
		printf("Failed to emulate code error with %u(%s).\n", err, uc_strerror(err));
		goto LB_ERROR_PROCESSING;
	}

	QueryPerformanceCounter(&curCounter);

#if !TEST
	// print executed time.
	{
		UINT64 elapsedCounter = curCounter.QuadPart - prevCounter.QuadPart;
		float elapsedSec = (float)elapsedCounter / (float)startFrequency.QuadPart;
		printf("\nElapsed Time: %lf ms.\n", elapsedSec * 1000.0f);
	}
	PrintResult(pUC);
#endif

	printf("[System] Emulation done.\n");

#if TEST
	if (InspectEmulationResult(pUC) == 0) // success
	{
		++g_SuccessCount;
	}
	else // fail type1
	{
		++g_FailProducingResultCount;
	}
#endif
	goto LB_RET;

LB_ERROR_PROCESSING:
	uc_reg_read(pUC, UC_ARM_REG_R0, &regValue);
	printf("Last R0 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R1, &regValue);
	printf("Last R1 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R2, &regValue);
	printf("Last R2 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R3, &regValue);
	printf("Last R3 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R4, &regValue);
	printf("Last R4 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R5, &regValue);
	printf("Last R5 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R6, &regValue);
	printf("Last R6 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R7, &regValue);
	printf("Last R7 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R8, &regValue);
	printf("Last R8 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R9, &regValue);
	printf("Last R9 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R10, &regValue);
	printf("Last R10 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R11, &regValue);
	printf("Last R11 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R12, &regValue);
	printf("Last R12 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R13, &regValue);
	printf("Last R13 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R14, &regValue);
	printf("Last R14 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_R15, &regValue);
	printf("Last R15 value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_PC, &regValue);
	printf("Last PC value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_SP, &regValue);
	printf("Last SP value: 0x%x\n", regValue);
	uc_reg_read(pUC, UC_ARM_REG_FP, &regValue);
	printf("Last FP value: 0x%x\n", regValue);
#if TEST
	// fail type2
	++g_FailEmulationCount;
#endif

LB_RET:
	if (pUC)
	{
		uc_close(pUC);
		pUC = NULL;
	}
}

int main()
{
	cs_err err;
	char option[8] = { 0, };
	unsigned char* pARM32_CODE = NULL;
	unsigned long long fileSize = 0;
	int codeLength = 0;

	err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &g_CSHandle);
	if (err != CS_ERR_OK)
	{
		printf("Failed to open cs engine error with %u(%s).\n", err, cs_strerror(err));
		goto LB_MAIN_RET;
	}

#if !TEST
	printf("Select bit flip option.\n");
	printf("Select an option. You can enter the option in three digits.\n");
	printf("The first number is instruction, the second number is stack, and the last number is register.\n");
	printf("Example) 111 ==> (Instruction + Stack + Register), 010 ==> (Stack), 101 ==> (Instruction + Register)\n");
	do
	{
		printf("==> ");
		scanf_s("%s", option, sizeof(option));
		if (strlen(option) != 3)
		{
			printf("try again.");
			continue;
		}
		if (option[0] - '0' > 1 || option[1] - '0' > 1 || option[2] - '0' > 1)
		{
			printf("try again.");
			continue;
		}
		g_FaultFlag |= (option[0] - '0' ? Instruction : 0);
		g_FaultFlag |= (option[1] - '0' ? Stack : 0);
		g_FaultFlag |= (option[2] - '0' ? Register : 0);
		break;
	} while (1);

	printf("Enter the probability of bit flip.\n");
	do
	{
		printf("==> ");
		scanf_s("%f", &g_ErrorProbability);
		if (g_ErrorProbability < 0.0 || g_ErrorProbability > 1.0f)
		{
			printf("Probability must be a prime number between 0 and 1.\n");
		}
		else
		{
			break;
		}
	} while (1);
#endif

	printf("Read compiled file...\n");
	fileSize = FileRead(&pARM32_CODE, &codeLength);
	if (fileSize == -1)
	{
		goto LB_MAIN_RET;
	}

#if !TEST
	// g_FaultFlag = (Instruction | Stack | Register);
	srand(time(NULL));
	TestFunc(pARM32_CODE, fileSize, codeLength);
#endif

#if TEST
	g_FaultFlag = (Instruction | Stack | Register);
	g_ErrorProbability = 0.001f;
	for (int i = 0; i < 1000; ++i)
	{
		srand(time(NULL));
		TestFunc(pARM32_CODE, fileSize, codeLength);
	}
	printf("Success Probability: %lf\n", (float)g_SuccessCount / 1000.0f * 100.0f);
	printf("Failed Producing Result Probability: %lf\n", (float)g_FailProducingResultCount / 1000.0f * 100.0f);
	printf("Failed Emulation Probability: %lf\n", (float)g_FailEmulationCount / 1000.0f * 100.0f);
#endif

	cs_close(&g_CSHandle);
	if (pARM32_CODE)
	{
		free(pARM32_CODE);
		pARM32_CODE = NULL;
	}

LB_MAIN_RET:
	return 0;
}