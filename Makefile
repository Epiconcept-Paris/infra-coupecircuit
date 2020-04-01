#
#	Makefile for nbphpsessd? binaries
#
BINS = nbphpsessd nbphpsess

CFLAGS	= -O -Wall
LDFLAGS	= -s

all:	$(BINS)

clean:
	rm -f core *.o $(BINS)
