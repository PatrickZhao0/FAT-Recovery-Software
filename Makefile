CC=gcc
CFLAGS=-g
LDFLAGS=-lcrypt

.PHONY: all
all: nyufile

nyufile: nyufile.o

nyufile.o: nyufile.c

.PHONY: clean
clean:
	rm -f *.o *.zip nyufile