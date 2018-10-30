CC=gcc
CFLAGS+=-Wall -g -DUSE_SLEEP
LDFLAGS+=-lpcap
EXE=$(patsubst %.c,%,$(wildcard *.c))

all: $(EXE)
clean:
	rm -f $(EXE) *.o *~
