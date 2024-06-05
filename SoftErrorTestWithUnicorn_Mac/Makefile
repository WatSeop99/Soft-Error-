LIB_UNICORN=-L/opt/homebrew/Cellar/unicorn/2.0.1.post1/lib/
LIB_CAPSTONE=-L/opt/homebrew/Cellar/capstone/5.0.1/lib/
INC_UNICORN=-I/opt/homebrew/Cellar/unicorn/2.0.1.post1/include/
INC_CAPSTONE=-I/opt/homebrew/Cellar/capstone/5.0.1/include/

all: UnicornTest.o Inspection.o
	clang UnicornTest.o Inspection.o $(LIB_UNICORN) -lunicorn $(LIB_CAPSTONE) -lcapstone -o test

UnicornTest.o: UnicornTest.c DataType.h Logger.h Inspection.h
	clang UnicornTest.c -Wall $(INC_UNICORN) $(INC_CAPSTONE) -c -o UnicornTest.o

Inspection.o: Inspection.c Inspection.h DataType.h
	clang Inspection.c -Wall $(INC_UNICORN) -c -o Inspection.o

clean:
	rm -rf *.o test