CC=gcc
CFLAGS+=-Wall -g -std=gnu99
LDFLAGS+=-lpcap
EXE=myripsniffer myripresponse myriprequest

all: $(EXE)

myripsniffer: src/myripsniffer.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
myriprequest: src/myriprequest.o src/socket.o src/utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
myripresponse: src/myripresponse.o src/socket.o src/utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

manual: manual.pdf
%.pdf: doc/%.md doc/%.bib
	pandoc --variable papersize=a4paper \
		--bibliography=$(word 2,$^) \
		--csl doc/cambridge-university-press-author-date.csl \
		--number-sections \
		--table-of-contents \
		-s -f markdown $< -o $@

clean:
	find . -name '*.o' -delete
	rm -f $(EXE)

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

.PHONY: all clean manual test-ripv1 test-ripv2 test-ripng test-combined test-md5
