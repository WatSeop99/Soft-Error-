#ifndef LOGGER
#define LOGGER

// #define TEST

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

#endif
