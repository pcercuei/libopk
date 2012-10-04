
DESTDIR ?= /usr/local

VERSION = 0.1

SONAME = libodx.so
LIBODX = $(SONAME).$(VERSION)

CC = $(CROSS_COMPILE)gcc
INSTALL ?= install

CFLAGS += -fPIC
LDFLAGS += -llzo2 -lz

OBJS = libodx.o unsqfs.o

all: $(LIBODX)

$(LIBODX): $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDFLAGS)

install: $(LIBODX)
	$(INSTALL) -m 0644 $(LIBODX) $(DESTDIR)/lib
	ln -s $(DESTDIR)/lib/$(LIBODX) $(DESTDIR)/lib/$(SONAME)
	$(INSTALL) -m 0644 odx.h $(DESTDIR)/include

clean:
	-rm -f $(OBJS) $(LIBODX)
