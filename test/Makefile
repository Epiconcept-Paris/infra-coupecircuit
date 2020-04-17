#
#	Makefile for BINS binaries
#
BINS = modif

#CFLAGS	= -Wall -ggdb -o -fsanitize=address -fno-omit-frame-pointer
CFLAGS	= -O -Wall
LDFLAGS	= -s

all:	$(BINS)

clean:
	rm -f core *.o $(BINS)

purge:
	rm -f core *.o $(BINS) nbphpsessd nbphpsess
