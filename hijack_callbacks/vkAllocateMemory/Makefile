CC=x86_64-w64-mingw32-gcc
CFLAGS=-Wall -Wextra -Wconversion -Werror -O0 -m64 -g 

.PHONY: all clean

all: main.c 
	$(CC) $(CFLAGS) main.c -o vkAllocateMemory.exe

clean:
	@rm -f *.exe
