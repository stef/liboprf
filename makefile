CFLAGS=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro -ftrapv -Wl,-z,noexecstack
LDFLAGS=-lsodium
CC=gcc
SOEXT=so
STATICEXT=a

SODIUM_NEWER_THAN_1_0_18 := $(shell pkgconf --atleast-version=1.0.19 libsodium; echo $$?)
ifeq ($(SODIUM_NEWER_THAN_1_0_18),1)
   CFLAGS+= -Iaux
   EXTRA_OBJECTS+= aux/kdf_hkdf_sha512.o
   EXTRA_SOURCES+= aux/kdf_hkdf_sha512.c
else
   CFLAGS+= -DHAVE_SODIUM_HKDF=1
endif

all: liboprf.$(SOEXT) liboprf.$(STATICEXT) toprf matrices thmult

asan: CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

liboprf.$(SOEXT): oprf.c toprf.c matrices.c $(EXTRA_SOURCES)
	$(CC) -shared $(CFLAGS) -Wl,-soname,liboprf.so -o liboprf.$(SOEXT) $^ $(LDFLAGS)

liboprf.$(STATICEXT): oprf.o toprf.o matrices.o $(EXTRA_OBJECTS)
	ar rcs $@ $^

toprf: oprf.c toprf.c main.c aux/kdf_hkdf_sha512.c
	gcc -g -o toprf oprf.c toprf.c main.c $(EXTRA_SOURCES) -lsodium

matrices: matrices.c
	gcc -g -Wall -o matrices -DUNIT_TEST=1 matrices.c -lsodium

thmult: thmult.c liboprf.a
	gcc -g -o thmult thmult.c liboprf.a -lsodium

clean:
	@rm -f *.o liboprf.so liboprf.a toprf aux/*.o matrices

PHONY: clean
