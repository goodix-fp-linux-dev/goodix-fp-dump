CFLAGS += $(shell pkg-config --cflags libusb-1.0)
LDLIBS += $(shell pkg-config --libs libusb-1.0)

PREFIX ?= /usr/local
bindir := $(PREFIX)/bin

CFLAGS += -DTRACE

all: goodix_fp_dump

install: goodix_fp_dump
	install -d $(DESTDIR)$(bindir)
	install -m 755 goodix_fp_dump $(DESTDIR)$(bindir)

clean:
	rm -rf *~ *.o goodix_fp_dump
