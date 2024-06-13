# Math_Compiled : Main.o Math.o
# 	clang -o Math_Compiled Main.o Math.o

# Math.o : Math.c Math.h
# 	clang -c -o Math.o Math.c

# Main.o : Main.c
# 	clang -c -o Main.o Main.c

# clean :
# 	rm *.o Math_Compiled

# arduino_compiled : arduino.o user.o
# 	arm-linux-gnueabihf-gcc -static -o arduino_compiled arduino.o user.o

# arduino.o : arduino.c arduino.h
# 	arm-linux-gnueabihf-gcc -static -c -o arduino.o arduino.c

# user.o : user.c arduino.h
# 	arm-linux-gnueabihf-gcc -static -c -o user.o user.c

# clean :
# 	rm *.o arduino_compiled


Math_Compiled : Main.o Math.o
	arm-none-eabi-gcc --specs=nosys.specs -static -o Math_Compiled Main.o Math.o

Math.o : Math.c Math.h
	arm-none-eabi-gcc --specs=nosys.specs -static -c -o Math.o Math.c

Main.o : Main.c
	arm-none-eabi-gcc --specs=nosys.specs -static -c -o Main.o Main.c 

clean :
	rm *.o Math_Compiled*