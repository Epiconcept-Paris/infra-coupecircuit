#
#	Makefile for nbphpsessd? binaries
#
#	Use: make debug to make debug-version of executables
#
BINS = nbphpsessd nbphpsess

prod:	CFLAGS	= -O -Wall
prod:	LDFLAGS	= -s

debug:	CFLAGS	= -Wall -fno-omit-frame-pointer -fsanitize=address -static-libasan

prod debug: all

all:	$(BINS)
	@for f in $(BINS); do \
	   test ! -f test/$$f -o $$f -nt test/$$f && cp -v $$f test || true; \
	done

clean:
	rm -f core *.o $(BINS); cd test && $(MAKE) --no-print-directory purge

.PHONY: prod debug all clean
