CFLAGS ?= -std=c99 -pedantic -Wall -Wextra -O2

# NOTE: vanilla libusb-1.0.8 can't live with pedantic errors
CFLAGS += -pedantic-errors

CFLAGS += -fno-common \
  -Wall \
  -Wextra \
  -Wformat=2 \
  -Winit-self \
  -Winline \
  -Wpacked \
  -Wp,-D_FORTIFY_SOURCE=2 \
  -Wpointer-arith \
  -Wlarger-than-65500 \
  -Wmissing-declarations \
  -Wmissing-format-attribute \
  -Wmissing-noreturn \
  -Wmissing-prototypes \
  -Wnested-externs \
  -Wold-style-definition \
  -Wredundant-decls \
  -Wsign-compare \
  -Wstrict-aliasing=2 \
  -Wstrict-prototypes \
  -Wswitch-enum \
  -Wundef \
  -Wunreachable-code \
  -Wwrite-strings

ifneq ($(CC),clang)
  CFLAGS += -Wunsafe-loop-optimizations

  # GCC >= 4.6
  CFLAGS += -Wunused-but-set-variable
endif

CFLAGS += $(shell pkg-config --cflags libusb-1.0)
LDLIBS += $(shell pkg-config --libs libusb-1.0)

PREFIX ?= /usr/local
bindir := $(PREFIX)/bin

CFLAGS += -DTRACE

all: goodix_fp_dump

install_udev_rules: contrib/55-goodix.rules
	sudo -v
	install -d $(DESTDIR)/lib/udev/rules.d
	install -m 644 contrib/55-goodix.rules $(DESTDIR)/lib/udev/rules.d
	udevadm control --reload
	usbreset $(lsusb -d 27c6: | cut -d ' ' -f 6)

install: goodix_fp_dump
	install -d $(DESTDIR)$(bindir)
	install -m 755 goodix_fp_dump $(DESTDIR)$(bindir)

clean:
	rm -rf *~ *.o goodix_fp_dump

test: goodix_fp_dump
	valgrind --leak-check=full --show-reachable=yes --track-origins=yes \
	  ./goodix_fp_dump
