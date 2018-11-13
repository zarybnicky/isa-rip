CC=gcc
CFLAGS+=-Wall -g -std=gnu99
LDFLAGS+=-lpcap
EXE=myripsniffer myripresponse myriprequest
DEP=$(patsubst %.c,%.d,$(wildcard src/*.c))

all: $(EXE)

%: src/%.c
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

manual: manual.pdf
%.pdf: doc/%.md doc/%.bib
	pandoc --variable papersize=a4paper \
		--bibliography=$(word 2,$^) \
		--csl doc/cambridge-university-press-author-date.csl \
		--number-sections \
		--table-of-contents \
		-s -f markdown $< -o $@

clean:
	rm -f $(EXE) $(DEP) *~ manual.pdf

test-ripv1: test/ripv1.pcap
	sudo tcpreplay -i lo -tK $<

test-ripv2: test/ripv2.pcap
	sudo tcpreplay -i lo -tK $<

test-ripng: test/ripng.pcap
	sudo tcpreplay -i lo -tK $<

test-combined: test/onlyrip-isa.pcapng
	sudo tcpreplay -i lo -tK $<

test-md5: test/rip-md5.pcapng
	sudo tcpreplay -i lo -tK $<

.PHONY: all clean manual test-ripv1 test-ripv2 test-ripng

%.d: %.c
	@set -e; rm -f $@; \
	 $(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	 sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 rm -f $@.$$$$

include $(DEP)
