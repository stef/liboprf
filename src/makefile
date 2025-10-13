PREFIX?=/usr/local
INCLUDES=-Inoise_xk/include -Inoise_xk/include/karmel -Inoise_xk/include/karmel/minimal
CFLAGS?=-Wall -O2 -g -ffunction-sections -fdata-sections \
		  -Werror=attributes -Werror=format-security -Werror=format-truncation -Werror=implicit-function-declaration \
		  -Wformat=2 -Wconversion -Wimplicit-fallthrough \
		  -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
		  -fstack-protector-strong -fasynchronous-unwind-tables -fpic \
		  -ftrapv -D_GLIBCXX_ASSERTIONS $(DEFINES) $(EXTRA_CFLAGS)

LIBS=-lsodium -loprf-noiseXK -Lnoise_xk
CC?=gcc
LD?=ld
OBJCOPY?=objcopy
STRIP?=strip
SOEXT?=so
STATICEXT?=a
SOVER=0
DEBUGDIR?=lib/debug/usr/lib

# To statically link the noiseXK library, use these LIBS (and comment out the other LIBS)
#LIBS=-lsodium -l:liboprf-noiseXK.a -Wl,--exclude-libs,ALL -Lnoise_xk

UNAME := $(if $(UNAME),$(UNAME),$(shell uname -s))
ARCH := $(if $(ARCH),$(ARCH),$(shell uname -m))
ifeq ($(UNAME),Darwin)
	SOEXT=dylib
	SOFLAGS=-Wl,-install_name,$(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT)
else
	CFLAGS+=-Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines \
			  -fsanitize=signed-integer-overflow -fsanitize-undefined-trap-on-error
			  #-fstrict-flex-arrays=3 -mbranch-protection=standard
	SOEXT=so
	SOFLAGS=-Wl,-soname,liboprf.$(SOEXT).$(SOVER)
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

PKGCONF_MISSING := $(shell pkgconf --version >/dev/null; echo $$?)
ifneq ($(PKGCONF_MISSING),0)
   $(error liboprf: Cannot find pkgconf)
endif

SODIUM_MISSING := $(shell pkgconf --exists libsodium; echo $$?)
ifneq ($(SODIUM_MISSING),0)
  $(error liboprf: Cannot find libsodium via pkgconf. Check that libsodium has been installed)
endif

SODIUM_NEWER_THAN_1_0_18 := $(shell pkgconf --atleast-version=1.0.19 libsodium; echo $$?)
ifneq ($(SODIUM_NEWER_THAN_1_0_18),0)
   INCLUDES+= -Iaux_
   EXTRA_SOURCES+= aux_/kdf_hkdf_sha256.c
   $(info liboprf: Using auxiliary sources because libsodium is too old)
else
   CFLAGS+= -DHAVE_SODIUM_HKDF=1
endif

all: liboprf.$(SOEXT) liboprf_release.$(STATICEXT) noise_xk/liboprf-noiseXK.$(SOEXT) liboprf.pc

android:
	$(MAKE) EXTRA_SOURCES+=jni.c liboprf.$(SOEXT)

LIBOPRF_SOURCES=oprf.c toprf.c dkg.c dkg-vss.c utils.c tp-dkg.c mpmult.c stp-dkg.c toprf-update.c
SOURCES=$(LIBOPRF_SOURCES) $(EXTRA_SOURCES)
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

# Uncomment to use $ORIGIN as the runtime search path
#SOFLAGS += -Wl,-rpath,'$$'ORIGIN

# Terminal colors: purely for UX, comment out if causing problems
decor = $(shell [ -t 0 ] && printf "\033[38;5;2m====" || printf "====")
endDecor = $(shell [ -t 0 ] && printf "====\033[0m" || printf "====")

debug: DEFINES=-DTRACE
debug: all

asan:
	CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
	ifeq ($(ARCH),x86_64)
		CFLAGS+=-fcf-protection=full
	endif
	ifeq ($(ARCH),parisc64)
	else ifeq ($(ARCH),parisc64)
	else ifeq ($(ARCH),armv7-a)
	else
		CFLAGS+=-fstack-clash-protection
	endif
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

AR ?= ar

aux_/kdf_hkdf_sha256.o: aux_/kdf_hkdf_sha256.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fvisibility=hidden $(INCLUDES) -o $@ -c $^

liboprf.$(SOEXT): liboprf_merged.o noise_xk/liboprf-noiseXK.$(SOEXT)
	$(info $(decor) Build dynamic release library: $@ $(endDecor))
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared $(SOFLAGS) -o $@ liboprf_merged.o $(LDFLAGS) $(LIBS)
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(STRIP) --strip-debug --strip-unneeded $@
	$(OBJCOPY) --add-gnu-debuglink=$@.debug $@

liboprf.$(SOEXT).debug: liboprf.$(SOEXT)

liboprf-corrupt-dkg.$(SOEXT): $(SOURCES) noise_xk/liboprf-noiseXK.$(SOEXT)
	$(info $(decor) Build unit test library: $@ $(endDecor))
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -DUNITTEST -DUNITTEST_CORRUPT -fPIC -shared $(SOFLAGS) -o $@ $(SOURCES) $(LDFLAGS) $(LIBS)

liboprf_merged.o: $(OBJECTS)
	$(info $(decor) Merge object files $(endDecor))
	$(LD) -r -o $@ $^

liboprf_merged_localized.o: liboprf_merged.o
	$(info $(decor) Localize symbols $(endDecor))
	objcopy --localize-hidden $^ $@

liboprf_release.$(STATICEXT): liboprf_merged_localized.o
	$(info $(decor) Build static release library: $@ $(endDecor))
	$(AR) rcs $@ $^

liboprf.$(STATICEXT): $(OBJECTS)
	$(AR) rcs $@ $^

noise_xk/liboprf-noiseXK.$(SOEXT):
	$(info $(decor) Compile vendorized noiseXK library: $@ $(endDecor))
	make -C noise_xk all

noise_xk/liboprf-noiseXK.$(STATICEXT):
	$(info $(decor) Compile vendorized noiseXK library: $@ $(endDecor))
	make -C noise_xk all

liboprf.pc:
	echo "prefix=$(PREFIX)" >liboprf.pc
	cat ../liboprf.pc >>liboprf.pc

clean:
	rm -f *.o liboprf.$(SOEXT) liboprf.$(STATICEXT) liboprf-corrupt-dkg.$(SOEXT)
	rm -f aux_/*.o
	make -C tests clean
	make -C noise_xk clean

install: install-oprf install-noiseXK

install-oprf: $(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT) \
	$(DESTDIR)$(PREFIX)/$(DEBUGDIR)/liboprf.$(SOEXT).debug \
	$(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT) \
	$(DESTDIR)$(PREFIX)/lib/pkgconfig/liboprf.pc \
	$(DESTDIR)$(PREFIX)/include/oprf/oprf.h \
	$(DESTDIR)$(PREFIX)/include/oprf/toprf.h \
	$(DESTDIR)$(PREFIX)/include/oprf/toprf-update.h \
	$(DESTDIR)$(PREFIX)/include/oprf/dkg.h \
	$(DESTDIR)$(PREFIX)/include/oprf/tp-dkg.h \
	$(DESTDIR)$(PREFIX)/include/oprf/stp-dkg.h \
	$(DESTDIR)$(PREFIX)/include/oprf/utils.h

install-noiseXK:
	make -C noise_xk install

uninstall: uninstall-oprf uninstall-noiseXK

uninstall-oprf:
	@ \
	if [ ! '$(strip $(DESTDIR)$(PREFIX))' ]; then echo 'liboprf: DESTDIR-PREFIX is empty!' && exit 1; fi; \
	if [ ! -d '$(strip $(DESTDIR)$(PREFIX))' ]; then echo 'liboprf: DESTDIR-PREFIX is not a folder' && exit 1; fi;

	rm -vf  '$(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT)'  '$(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT)'
	rm -vf  '$(DESTDIR)$(PREFIX)/include/oprf/oprf.h'  '$(DESTDIR)$(PREFIX)/include/oprf/toprf.h'
	rm -vf  '$(DESTDIR)$(PREFIX)/include/oprf/dkg.h'  '$(DESTDIR)$(PREFIX)/include/oprf/toprf-update.h'
	rm -vf  '$(DESTDIR)$(PREFIX)/include/oprf/utils.h' '$(DESTDIR)$(PREFIX)/lib/pkgconfig/liboprf.pc'
	rm -vf  '$(DESTDIR)$(PREFIX)/include/oprf/tp-dkg.h' '$(DESTDIR)$(PREFIX)/include/oprf/stp-dkg.h'
	rm -vf  '$(DESTDIR)$(PREFIX)/$(DEBUGDIR)/liboprf.$(SOEXT).debug'
	rmdir -v '$(DESTDIR)$(PREFIX)/include/oprf/'

uninstall-noiseXK:
	make -C noise_xk uninstall

$(DESTDIR)$(PREFIX)/lib/liboprf.$(SOEXT): liboprf.$(SOEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp $< $@.$(SOVER)
	ln -sf $@.$(SOVER) $@

$(DESTDIR)$(PREFIX)/lib/liboprf.$(STATICEXT): liboprf_release.$(STATICEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp $< $@

$(DESTDIR)$(PREFIX)/lib/pkgconfig/liboprf.pc: liboprf.pc
	mkdir -p $(DESTDIR)$(PREFIX)/lib/pkgconfig
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/oprf.h: oprf.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/toprf.h: toprf.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/toprf-update.h: toprf-update.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/dkg.h: dkg.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/tp-dkg.h: tp-dkg.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/stp-dkg.h: stp-dkg.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/include/oprf/utils.h: utils.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/oprf
	cp $< $@

$(DESTDIR)$(PREFIX)/$(DEBUGDIR)/liboprf.$(SOEXT).debug: liboprf.$(SOEXT).debug
	mkdir -p $(DESTDIR)$(PREFIX)/$(DEBUGDIR)
	cp $< $@

test: liboprf-corrupt-dkg.$(SOEXT) liboprf.$(STATICEXT) noise_xk/liboprf-noiseXK.$(STATICEXT)
	make -C tests tests
	make -C noise_xk test

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC $(INCLUDES) -c $< -o $@

PHONY: clean
