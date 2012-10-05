
DESTDIR ?= /usr/local

VERSION = 0.1

SONAME = libopk.so
LIBOPK = $(SONAME).$(VERSION)

CC = $(CROSS_COMPILE)gcc
INSTALL ?= install

CFLAGS += -fPIC
LDFLAGS += -llzo2 -lz

OBJS = libopk.o unsqfs.o

all: $(LIBOPK)

$(LIBOPK): $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDFLAGS)

install: $(LIBOPK)
	$(INSTALL) -m 0644 $(LIBOPK) $(DESTDIR)/lib
	-ln -s $(DESTDIR)/lib/$(LIBOPK) $(DESTDIR)/lib/$(SONAME)
	$(INSTALL) -m 0644 opk.h $(DESTDIR)/include

clean:
	-rm -f $(OBJS) $(LIBOPK)
