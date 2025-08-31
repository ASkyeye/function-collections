CC=x86_64-w64-mingw32-gcc
CFLAGS=-Wall -Wextra -Wconversion -Werror -O0 -m64 -g 

.PHONY: all clean

all: fetch_peb_using_verifier_dll.c 
	$(CC) $(CFLAGS) fetch_peb_using_verifier_dll.c -o fetch_peb_using_verifier_dll.exe

clean:
	@rm -f *.exe
