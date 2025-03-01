PREFIX?=/usr/local
LDFLAGS=-lsodium
SOURCES=src/Noise_XK.c src/XK.c
INCLUDES=-Iinclude -I include/karmel -I include/karmel/minimal
CFLAGS 	?= -Wall -Wextra -Werror -std=c11 -Wno-unused-variable \
				-Wno-unknown-warning-option -Wno-unused-but-set-variable \
				-Wno-unused-parameter -Wno-infinite-recursion -fpic \
				-g -fwrapv -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM \
				-O2 -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
				-fasynchronous-unwind-tables -fpic \
				-Werror=format-security -Werror=implicit-function-declaration \
				-ftrapv $(INCLUDES)
CC?=gcc

SOEXT?=so
STATICEXT?=a
SOVER=0

UNAME := $(shell uname -s)
ARCH := $(shell uname -m)
ifeq ($(UNAME),Darwin)
   SOEXT=dylib
   SOFLAGS=-Wl,-install_name,$(DESTDIR)$(PREFIX)/lib/liboprf-noiseXK.$(SOEXT)
else
   ifeq ($(shell uname),Linux)
	CFLAGS 	+= -Wl,--error-unresolved-symbols -Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack
	SOEXT=so
	SOFLAGS=-Wl,-soname,liboprf-noiseXK.$(SOEXT).$(SOVER)
   endif
   ifeq ($(ARCH),x86_64)
   	CFLAGS+=-fcf-protection=full 
   endif
   ifeq ($(ARCH),parisc64)
   else ifeq ($(ARCH),parisc64)
   else
   	CFLAGS+=-fstack-clash-protection
   endif
endif

mingw64: CC=x86_64-w64-mingw32-gcc
mingw64: SOEXT=dll
mingw64: STATICEXT=lib
mingw64: EXT=.exe
mingw64: MAKETARGET=mingw
mingw64: CFLAGS=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
               -fasynchronous-unwind-tables -fpic -Werror=format-security \
               -Werror=implicit-function-declaration -ftrapv $(DEFINES) $(INCLUDES) \
               -I../win/libsodium-win64/include/sodium -I../win/libsodium-win64/include
mingw64: LDFLAGS+=-L. -L.. -L../win/libsodium-win64/lib/ -Wl,-Bstatic -lsodium -Wl,-Bdynamic
mingw64: liboprf-noiseXK.$(SOEXT)

OBJS 	+= $(patsubst %.c,%.o,$(SOURCES))

all: liboprf-noiseXK.$(STATICEXT) liboprf-noiseXK.$(SOEXT)

AR ?= ar

%.$(STATICEXT): $(OBJS)
	$(AR) rcs $@ $^

%.$(SOEXT): $(OBJS)
	$(CC) $(CFLAGS) -fPIC -shared $(SOFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.so *.a src/*.o
	make -C example clean

liboprf-noiseXK.$(SOEXT).$(SOVER): liboprf-noiseXK.$(SOEXT)
	ln -sf $^ $@

install: $(DESTDIR)$(PREFIX)/lib/liboprf-noiseXK.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/liboprf-noiseXK.$(STATICEXT) $(DESTDIR)$(PREFIX)/include/oprf/noiseXK

uninstall: $(DESTDIR)$(PREFIX)/lib/liboprf-noiseXK.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/liboprf-noiseXK.$(STATICEXT) $(DESTDIR)$(PREFIX)/include/oprf/noiseXK
	rm -rf $^

$(DESTDIR)$(PREFIX)/lib/liboprf-noiseXK.$(SOEXT): liboprf-noiseXK.$(SOEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib/
	cp $< $@.$(SOVER)
	ln -sf $@.$(SOVER) $@

$(DESTDIR)$(PREFIX)/lib/liboprf-noiseXK.$(STATICEXT): liboprf-noiseXK.$(STATICEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib/
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/noiseXK: include
	cp -r $< $@

test: liboprf-noiseXK.$(SOEXT).$(SOVER)
	make -C example test
