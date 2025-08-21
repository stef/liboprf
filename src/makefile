PREFIX?=/usr/local
INCLUDES=-Inoise_xk/include -Inoise_xk/include/karmel -Inoise_xk/include/karmel/minimal
CFLAGS?=-march=native -Wall -O2 -g -ffunction-sections -fdata-sections \
		  -Werror=attributes -Werror=format-security -Werror=format-truncation -Werror=implicit-function-declaration \
		  -Wformat=2 -Wconversion -Wimplicit-fallthrough \
		  -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
		  -fstack-protector-strong -fasynchronous-unwind-tables -fpic \
		  -ftrapv -D_GLIBCXX_ASSERTIONS $(DEFINES)

LDFLAGS?=-lsodium -loprf-noiseXK -Lnoise_xk
CC?=gcc
SOEXT?=so
STATICEXT?=a
SOVER=0

# To statically link the noiseXK library, use these LDFLAGS (and comment out the other LDFLAGS)
#LDFLAGS?=-lsodium -l:liboprf-noiseXK.a -Wl,--exclude-libs,ALL -Lnoise_xk

UNAME := $(shell uname -s)
ARCH := $(shell uname -m)
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
   CFLAGS+= -Iaux_
   EXTRA_SOURCES+= aux_/kdf_hkdf_sha256.c
   $(info liboprf: Using auxiliary sources because libsodium is too old)
else
   CFLAGS+= -DHAVE_SODIUM_HKDF=1
endif

CFLAGS+=$(INCLUDES)

LIBOPRF_SOURCES=oprf.c toprf.c dkg.c dkg-vss.c utils.c tp-dkg.c mpmult.c stp-dkg.c toprf-update.c
SOURCES=$(LIBOPRF_SOURCES) $(EXTRA_SOURCES)
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

# Uncomment to use $ORIGIN as the runtime search path
#SOFLAGS += -Wl,-rpath,'$$'ORIGIN

# Terminal colors: purely for UX, comment out if causing problems
decor = $(shell [ -t 0 ] && printf "\033[38;5;2m====" || printf "====")
endDecor = $(shell [ -t 0 ] && printf "====\033[0m" || printf "====")

all: liboprf.$(SOEXT) liboprf_release.$(STATICEXT) noise_xk/liboprf-noiseXK.$(SOEXT) liboprf.pc

debug: DEFINES=-DTRACE
debug: all

asan:
	CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
	ifeq ($(ARCH),x86_64)
		CFLAGS+=-fcf-protection=full
	endif
	ifeq ($(ARCH),parisc64)
	else ifeq ($(ARCH),parisc64)
	else
		CFLAGS+=-fstack-clash-protection
	endif
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

AR ?= ar

liboprf.$(SOEXT): liboprf_merged.o noise_xk/liboprf-noiseXK.$(SOEXT)
	$(info $(decor) Build dynamic release library: $@ $(endDecor))
	$(CC) $(CFLAGS) -fPIC -shared $(SOFLAGS) -o $@ liboprf_merged.o $(LDFLAGS)

liboprf-corrupt-dkg.$(SOEXT): liboprf_merged.o noise_xk/liboprf-noiseXK.$(SOEXT)
	$(info $(decor) Build unit test library: $@ $(endDecor))
	$(CC) $(CFLAGS) -DUNITTEST -DUNITTEST_CORRUPT -fPIC -shared $(SOFLAGS) -o $@ liboprf_merged.o $(LDFLAGS)

liboprf_merged.o: $(OBJECTS)
	$(info $(decor) Merge object files $(endDecor))
	ld -r -o $@ $^

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

test: liboprf-corrupt-dkg.$(SOEXT) liboprf.$(STATICEXT) noise_xk/liboprf-noiseXK.$(STATICEXT)
	make -C tests tests
	make -C noise_xk test

PHONY: clean

# Dynamic rules area

# NOTE:
# 1. The $(__NL__)'s are required - don't remove them!
# 2. Every variable reference must be double-escaped in the defines ($VAR -> $$VAR)
# 3. There is one exception to the rule: do not escape $1, $2, etc. and $__NL__
# 4. Change `eval` to `info` to debug. Also, GMake has a `--dry-run` option

# "New line" variable
# Don't remove these empty comments!
define __NL__
#
#
endef

# Compile a first-party C file into an object file
# Input params:
#   $(1) = C file path
define compileObject
$(__NL__)

$(1:.c=.o) : $(1)
	$$(info )
	$$(info $$(decor) Compile C source: $$^ $$(endDecor))
	$$(CC) $$(CFLAGS) $$(INCLUDES) -o $$@ -c $$^

$(__NL__)
endef

# Compile a vendorized libsodium C file into an object file
# Static linking DEFINES can be found at <https://libsodium.gitbook.io/doc/usage>
# Input params:
#   $(1) = C file path
define compileSodiumObject
$(__NL__)

$(1:.c=.o) : $(1)
	$$(info )
	$$(info $$(decor) Compile vendorized libsodium source: $$^ $$(endDecor))
	$$(CC) $$(CFLAGS) -fvisibility=hidden -DSODIUM_STATIC=1 -DSODIUM_EXPORT="" $$(INCLUDES) -o $$@ -c $$^

$(__NL__)
endef

# Compile liboprf C files
$(foreach var,$(LIBOPRF_SOURCES), \
    $(eval $(call compileObject,$(var) )) \
)

# Compile vendor C files
$(foreach var,$(EXTRA_SOURCES), \
    $(eval $(call compileSodiumObject,$(var) )) \
)

# END dynamic rules section
