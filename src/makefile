PREFIX?=/usr/local
INCLUDES=-Inoise_xk/include -Inoise_xk/include/karmel -Inoise_xk/include/karmel/minimal
CFLAGS?=-march=native -Wall -O2 -g \
		  -Werror=format-security -Werror=implicit-function-declaration \
		  -Wformat=2 -Wconversion -Wimplicit-fallthrough \
		  -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
		  -fstack-protector-strong -fasynchronous-unwind-tables -fpic \
		  -ftrapv -D_GLIBCXX_ASSERTIONS

LDFLAGS?=-lsodium -loprf-noiseXK -Lnoise_xk
CC?=gcc
SOEXT?=so
STATICEXT?=a
SOVER=0

UNAME := $(shell uname -s)
ARCH := $(shell uname -m)
ifeq ($(UNAME),Darwin)
	SOEXT=dylib
	SOFLAGS=-Wl,-install_name,$(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT)
else
	CFLAGS+=-Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines \
			  -fsanitize=signed-integer-overflow -fsanitize-undefined-trap-on-error \
			  -fstack-clash-protection 
			  #-fstrict-flex-arrays=3 -mbranch-protection=standard
	SOEXT=so
	SOFLAGS=-Wl,-soname,liboprf.$(SOEXT).$(SOVER)	
endif

ifeq ($(ARCH),x86_64)
	CFLAGS+=-fcf-protection=full 
endif

CFLAGS+=$(INCLUDES)

SOURCES=oprf.c toprf.c dkg.c utils.c tp-dkg.c $(EXTRA_SOURCES)
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

all: liboprf.$(SOEXT) liboprf.$(STATICEXT) toprf noise_xk/liboprf-noiseXK.$(SOEXT)

asan: 
	CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -fstack-clash-protection -Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
	ifeq ($(ARCH),x86_64)
		CFLAGS+=-fcf-protection=full 
	endif
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

AR ?= ar

liboprf.$(SOEXT): $(SOURCES) noise_xk/liboprf-noiseXK.$(SOEXT)
	$(CC) $(CFLAGS) -fPIC -shared $(SOFLAGS) -o $@ $^ $(LDFLAGS)
  
liboprf-corrupt-dkg.$(SOEXT): $(SOURCES) noise_xk/liboprf-noiseXK.$(SOEXT)
	$(CC) $(CFLAGS) -DUNITTEST -DUNITTEST_CORRUPT -fPIC -shared $(SOFLAGS) -o $@ $^ $(LDFLAGS)

liboprf.$(STATICEXT): $(OBJECTS)
	$(AR) rcs $@ $^

noise_xk/liboprf-noiseXK.$(SOEXT):
	make -C noise_xk all

noise_xk/liboprf-noiseXK.$(STATICEXT):
	make -C noise_xk all

toprf: oprf.c toprf.c main.c
	$(CC) -g -o toprf oprf.c toprf.c main.c $(EXTRA_SOURCES) -lsodium

clean:
	rm -f *.o liboprf.$(SOEXT) liboprf.$(STATICEXT) toprf liboprf-corrupt-dkg.$(SOEXT)
	make -C tests clean
	make -C noise_xk clean

install: install-oprf install-noiseXK

install-oprf: $(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT) $(DESTDIR)$(PREFIX)/include/oprf/oprf.h $(DESTDIR)$(PREFIX)/include/oprf/toprf.h $(DESTDIR)$(PREFIX)/include/oprf/dkg.h $(DESTDIR)$(PREFIX)/include/oprf/tp-dkg.h

install-noiseXK:
	make -C noise_xk install

uninstall: uninstall-oprf uninstall-noiseXK

uninstall-oprf: $(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT) $(DESTDIR)$(PREFIX)/include/oprf/oprf.h $(DESTDIR)$(PREFIX)/include/oprf/toprf.h $(PREFIX)/include/oprf/dkg.h
	rm $^
	rmdir $(PREFIX)/include/oprf/

uninstall-noiseXK:
	make -C noise_xk uninstall

$(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT): liboprf.$(SOEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp $< $@.$(SOVER)
	ln -sf $@.$(SOVER) $@

$(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT): liboprf.$(STATICEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/oprf.h: oprf.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/toprf.h: toprf.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/dkg.h: dkg.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/tp-dkg.h: tp-dkg.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

test: liboprf-corrupt-dkg.$(SOEXT) liboprf.$(STATICEXT) noise_xk/liboprf-noiseXK.$(STATICEXT)
	make -C tests tests
	make -C noise_xk test

PHONY: clean
