#ifndef LOGGER
#define LOGGER

#define TEST 1 // Test Mode.

typedef struct _registerInfo {
	unsigned int LastRegisterNo;
	unsigned int Mask;
	unsigned int Value;
} RegisterInfo;

typedef struct _stackInfo {
	unsigned int Address;
	unsigned int Offset;
	unsigned int Value;
	unsigned int Mask;
} StackInfo;

typedef struct _instructionInfo {
	unsigned int PCValue;
	unsigned int Mask;
} InstructionInfo;

#endif
