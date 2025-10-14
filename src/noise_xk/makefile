PREFIX?=/usr/local
LIBS=-lsodium
SOURCES=src/Noise_XK.c src/XK.c
INCLUDES= -Iinclude -I include/karmel -I include/karmel/minimal
CFLAGS 	?= -Wall -Wextra -Werror -std=c11 -Wno-unused-variable \
				-Wno-unknown-warning-option -Wno-unused-but-set-variable \
				-Wno-unused-parameter -Wno-infinite-recursion -fpic \
				-fwrapv -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM \
				-O2 -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
				-fasynchronous-unwind-tables -fpic \
				-Werror=format-security -Werror=implicit-function-declaration \
				-ftrapv
CC?=gcc

SOEXT?=so
STATICEXT?=a
SOVER=0

UNAME := $(if $(UNAME),$(UNAME),$(shell uname -s))
ARCH := $(if $(ARCH),$(ARCH),$(shell uname -m))
ifeq ($(UNAME),Darwin)
   SOEXT=dylib
   SOFLAGS=-Wl,-install_name,$(DESTDIR)$(PREFIX)/lib/liboprf-noiseXK.$(SOEXT)
else
   ifeq ($(UNAME),Linux)
	CFLAGS 	+= -Wl,--error-unresolved-symbols -Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack
	SOEXT=so
	SOFLAGS=-Wl,-soname,liboprf-noiseXK.$(SOEXT).$(SOVER)
   endif
   ifeq ($(ARCH),x86_64)
   	CFLAGS+=-fcf-protection=full 
   endif
   ifeq ($(ARCH),parisc64)
   else ifeq ($(ARCH),parisc64)
   else ifeq ($(ARCH),armv7-a)
   else
   	CFLAGS+=-fstack-clash-protection
   endif
endif

OBJS 	+= $(patsubst %.c,%.o,$(SOURCES))

android: CFLAGS+=-I$(SODIUM) -I$(SODIUM)/sodium
android: LDFLAGS+=-L.
android: liboprf-noiseXK.$(SOEXT)

all: liboprf-noiseXK.$(STATICEXT) liboprf-noiseXK.$(SOEXT)

AR ?= ar

%.$(STATICEXT): $(OBJS)
	$(AR) rcs $@ $^

%.$(SOEXT): $(OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared $(SOFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS) $(LIBS)

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

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC $(INCLUDES) -c $< -o $@
