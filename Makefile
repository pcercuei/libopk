USE_GZIP ?= 1
USE_LZO ?= 0

PREFIX ?= /usr/local

VERSION_MAJOR = 1
VERSION_MINOR = 0

LIBNAME = libopk.so
SONAME = $(LIBNAME).$(VERSION_MAJOR)
LIBOPK = $(SONAME).$(VERSION_MINOR)

CC = $(CROSS_COMPILE)gcc
ANALYZER = clang --analyze
INSTALL ?= install

# Note: Code will compile as C99 too, but without static asserts.
CFLAGS += -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra \
	-fPIC -fvisibility=hidden \
	-DUSE_GZIP=$(USE_GZIP) -DUSE_LZO=$(USE_LZO)
LDFLAGS += -lini

ifeq ($(USE_GZIP),1)
LDFLAGS += -lz
endif
ifeq ($(USE_LZO),1)
LDFLAGS += -llzo2
endif

OBJS = libopk.o unsqfs.o

.PHONY: all analyze clean \
	install install-bin install-lib \
	uninstall uninstall-bin uninstall-lib

all: $(LIBOPK) opkinfo opkrun

opkinfo: opkinfo.c $(LIBOPK)
	$(CC) -o $@ $^ $(CFLAGS)

opkrun: opkrun.c $(LIBOPK)
	$(CC) -o $@ $^ $(CFLAGS)

$(LIBOPK): $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDFLAGS)

analyze:
	$(ANALYZER) $(CFLAGS) $(OBJS:%.o=%.c)

install-bin: opkinfo opkrun
	$(INSTALL) -D $< $(DESTDIR)$(PREFIX)/bin/$<

install-lib: $(LIBOPK)
	$(INSTALL) -D $(LIBOPK) $(DESTDIR)$(PREFIX)/lib/$(LIBOPK)
	ln -sf $(LIBOPK) $(DESTDIR)$(PREFIX)/lib/$(SONAME)

install: install-bin install-lib
	$(INSTALL) -D -m 0644 opk.h $(DESTDIR)$(PREFIX)/include/opk.h
	ln -sf $(SONAME) $(DESTDIR)$(PREFIX)/lib/$(LIBNAME)

uninstall-bin:
	rm -f $(DESTDIR)$(PREFIX)/bin/opkinfo $(DESTDIR)$(PREFIX)/bin/opkrun

uninstall-lib:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(LIBOPK) $(DESTDIR)$(PREFIX)/lib/$(SONAME)

uninstall: uninstall-bin uninstall-lib
	rm -f $(DESTDIR)$(PREFIX)/include/opk.h $(DESTDIR)$(PREFIX)/lib/$(LIBNAME)

clean:
	rm -f $(OBJS) $(LIBOPK) opkinfo
