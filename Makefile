#
#	Makefile for nbphpsessd? binaries
#
BINS = nbphpsessd nbphpsess sesswatch

CFLAGS	= -Wall -ggdb -o -fsanitize=address -fno-omit-frame-pointer
#CFLAGS	= -O -Wall
#LDFLAGS	= -s

all:	$(BINS)

clean:
	rm -f core *.o $(BINS)
