CFLAGS?=-Wall
LDFLAGS?=-static
all:	coap
install:	coap
	strip coap
	mkdir -p $(DESTDIR)/$(PREFIX)/bin
	cp -p coap $(DESTDIR)/$(PREFIX)/bin
clean:
	rm -f *.o coap
