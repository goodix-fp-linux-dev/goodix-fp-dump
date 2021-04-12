LDLIBS += -lusb-1.0

PREFIX ?= /usr/local

all: goodix_fp_dump

install: goodix_fp_dump
	install -CD goodix_fp_dump -t $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/goodix_fp_dump

clean:
	rm -f goodix_fp_dump
