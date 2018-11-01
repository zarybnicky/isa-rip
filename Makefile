CC=gcc
CFLAGS+=-Wall -g -DUSE_SLEEP
LDFLAGS+=-lpcap
EXE=$(patsubst %.c,%,$(wildcard *.c))

all: $(EXE) manual.pdf
clean:
	rm -f $(EXE) *.o *~ manual.pdf

%.pdf: %.md
	pandoc --variable papersize=a4paper\
		--number-sections \
		--table-of-contents \
		-s -f markdown $< -o $@
