#
#	Makefile for nbphpsessd? binaries
#
BINS = nbphpsessd nbphpsess

#CFLAGS	= -Wall -fsanitize=address -fno-omit-frame-pointer
CFLAGS	= -O -Wall
LDFLAGS	= -s

all:	$(BINS)
	@for f in $(BINS); do \
	   test ! -f test/$$f -o $$f -nt test/$$f && cp -v $$f test || true; \
	done

clean:
	rm -f core *.o $(BINS); cd test && $(MAKE) purge
