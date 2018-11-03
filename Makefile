CC=gcc
CFLAGS+=-Wall -g
LDFLAGS+=-lpcap
EXE=$(patsubst %.c,%,$(wildcard *.c))

all: $(EXE) manual.pdf
clean:
	rm -f $(EXE) *.o *~ manual.pdf

%.pdf: %.md %.bib
	pandoc --variable papersize=a4paper \
		--filter pandoc-citeproc \
		--bibliography=$(word 2,$^) \
		--number-sections \
		--table-of-contents \
		-s -f markdown $< -o $@
