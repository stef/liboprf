CFLAGS?=-march=native -Wall -O2 -g \
		  -Werror=format-security -Werror=implicit-function-declaration \
		  -Wformat=2 -Wconversion -Wtrampolines -Wimplicit-fallthrough \
		  -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
		  -fstack-protector-strong -fasynchronous-unwind-tables -fpic \
		  -fstack-clash-protection -ftrapv \
		  -D_GLIBCXX_ASSERTIONS -fcf-protection=full #-mbranch-protection=standard -fstrict-flex-arrays=3 

LDFLAGS?=-lsodium
CC?=gcc
SOEXT?=so
STATICEXT?=a
SOVER=0

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
	SOEXT=dylib
	SOFLAGS=-Wl,-install_name,liboprf.$(SOEXT)
else
	CFLAGS+=-Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now
	SOEXT=so
	SOFLAGS=-Wl,-soname,liboprf.$(SOEXT).$(SOVER)
endif

SOURCES=oprf.c toprf.c dkg.c utils.c  $(EXTRA_SOURCES)
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

all: liboprf.$(SOEXT) liboprf.$(STATICEXT) toprf dkg

asan: CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

liboprf.$(SOEXT): $(SOURCES)
	$(CC) $(CFLAGS) -fPIC -shared $(SOFLAGS) -o $@ $^ $(LDFLAGS)

liboprf.$(STATICEXT): $(OBJECTS)
	ar rcs $@ $^

toprf: oprf.c toprf.c main.c
	gcc -g -o toprf oprf.c toprf.c main.c $(EXTRA_SOURCES) -lsodium

dkg: dkg.c utils.c liboprf.a
	gcc -g -DUNIT_TEST -o dkg dkg.c utils.c liboprf.a -lsodium

clean:
	rm -f *.o liboprf.so liboprf.a toprf dkg
	make -C tests clean
	make -C noise_xk clean

install: install-oprf install-noiseXK

install-oprf: $(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT) $(DESTDIR)$(PREFIX)/include/oprf/oprf.h $(DESTDIR)$(PREFIX)/include/oprf/toprf.h $(DESTDIR)$(PREFIX)/include/oprf/dkg.h

install-noiseXK:
	make -C noise_xk install

uninstall: uninstall-oprf uninstall-noiseXK

uninstall-oprf: $(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT) $(DESTDIR)$(PREFIX)/include/oprf/oprf.h $(DESTDIR)$(PREFIX)/include/oprf/toprf.h $(PREFIX)/include/oprf/dkg.h
	rm $^
	rmdir $(PREFIX)/include/oprf/

uninstall-noiseXK:
	make -C noise_xk uninstall

$(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT): liboprf.$(SOEXT)
	install -D $< $@.$(SOVER)
	ln -sf $@.$(SOVER) $@

$(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT): liboprf.$(STATICEXT)
	install -D $< $@

$(DESTDIR)$(PREFIX)/include/oprf/oprf.h: oprf.h
	install -D $< $@

$(DESTDIR)$(PREFIX)/include/oprf/toprf.h: toprf.h
	install -D $< $@

$(DESTDIR)$(PREFIX)/include/oprf/dkg.h: dkg.h
	install -D $< $@

test:
	make -C tests tests
	make -C noise_xk test

PHONY: clean
