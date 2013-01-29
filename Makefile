USE_GZIP ?= 1
USE_LZO ?= 0

PREFIX ?= /usr/local

VERSION_MAJOR = 0
VERSION_MINOR = 1

LIBNAME = libopk.so
SONAME = $(LIBNAME).$(VERSION_MAJOR)
LIBOPK = $(SONAME).$(VERSION_MINOR)

CC = $(CROSS_COMPILE)gcc
INSTALL ?= install

CFLAGS += -std=c99 -Wall -Wextra -fPIC \
	-DUSE_GZIP=$(USE_GZIP) -DUSE_LZO=$(USE_LZO)
ifeq ($(USE_GZIP),1)
LDFLAGS += -lz
endif
ifeq ($(USE_LZO),1)
LDFLAGS += -llzo2
endif

OBJS = libopk.o unsqfs.o

.PHONY: all clean install install-lib

all: $(LIBOPK)

$(LIBOPK): $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDFLAGS)

install-lib: $(LIBOPK)
	$(INSTALL) -D $(LIBOPK) $(DESTDIR)$(PREFIX)/lib/$(LIBOPK)
	ln -sf $(LIBOPK) $(DESTDIR)$(PREFIX)/lib/$(SONAME)

install: install-lib
	$(INSTALL) -D -m 0644 opk.h $(DESTDIR)$(PREFIX)/include/opk.h
	ln -sf $(SONAME) $(DESTDIR)$(PREFIX)/lib/$(LIBNAME)

clean:
	rm -f $(OBJS) $(LIBOPK)
