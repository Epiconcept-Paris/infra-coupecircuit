#
#	Makefile for BINS binaries
#
#	Use: make debug to make debug-version of executables
#
BINS = modif real mkd

prod:	CFLAGS	= -O -Wall
prod:	LDFLAGS	= -s

debug:	CFLAGS	= -Wall -fno-omit-frame-pointer -fsanitize=address -static-libasan

prod debug: all

all:	$(BINS)

clean:
	rm -f $(BINS) core *.o

purge:
	test -x nbphpsessd && ./nbphpsessd -k 2>/dev/null; \
	rm -f $(BINS) core *.o *.log *.pid nbphpsessd nbphpsess

.PHONY: prod debug all clean purge
