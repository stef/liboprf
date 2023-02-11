CFLAGS=-Isss -march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro -ftrapv -Wl,-z,noexecstack
LDFLAGS=-lsodium
CC=gcc
SOEXT=so
STATICEXT=a

SODIUM_NEWER_THAN_1_0_18 := $(shell pkgconf --atleast-version=1.0.19 libsodium; echo $$?)
ifeq ($(SODIUM_NEWER_THAN_1_0_18),1)
   CFLAGS+= -Iaux
   EXTRA_OBJECTS+= aux/kdf_hkdf_sha512.o
else
   CFLAGS+= -DHAVE_SODIUM_HKDF=1
endif

asan: CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

liboprf.$(SOEXT): oprf.c toprf.c $(EXTRA_OBJECTS)
	$(CC) -shared $(CFLAGS) -Wl,-soname,liboprf.so -o liboprf.$(SOEXT) $^ $(LDFLAGS)

liboprf.$(STATICEXT): oprf.o toprf.o $(EXTRA_OBJECTS)
	ar rcs $@ $^

toprf: oprf.c toprf.c main.c aux/kdf_hkdf_sha512.c
	gcc -Isss -o toprf oprf.c toprf.c main.c aux/kdf_hkdf_sha512.c -lsodium

clean:
	@rm -f *.o liboprf.so liboprf.a toprf aux/*.o

PHONY: clean
