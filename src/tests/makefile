CFLAGS?= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
		   -fstack-protector-strong -fasynchronous-unwind-tables -fpic \
		   -ftrapv -D_GLIBCXX_ASSERTIONS \
		   -Wl,-z,defs -Wl,-z,relro \
		   -Wl,-z,noexecstack -Wl,-z,now -fsanitize=signed-integer-overflow \
		   -fsanitize-undefined-trap-on-error
CC?=gcc
INCLUDES=-I.. -I../noise_xk/include -I../noise_xk/include/karmel/ -I../noise_xk/include/karmel/minimal/

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	CFLAGS+=-fcf-protection=full
endif
ifeq ($(ARCH),parisc64)
else ifeq ($(ARCH),parisc64)
else
	CFLAGS+=-fstack-clash-protection
endif

SODIUM_NEWER_THAN_1_0_18 := $(shell pkgconf --atleast-version=1.0.19 libsodium; echo $$?)
ifeq ($(SODIUM_NEWER_THAN_1_0_18),1)
   CFLAGS+= -I../aux_
   EXTRA_SOURCES+= ../aux_/kdf_hkdf_sha256.c
else
   CFLAGS+= -DHAVE_SODIUM_HKDF=1
endif

all: tv1 tv2 dkg toprf tp-dkg tp-dkg-corrupt mpmult stp-dkg stp-dkg-corrupt toprf-update toprf-update-corrupt

tv1: test.c cfrg_oprf_test_vectors.h cfrg_oprf_test_vector_decl.h ../oprf.c ../utils.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g -o tv1 -DCFRG_TEST_VEC=1 -DCFRG_OPRF_TEST_VEC=1 -DTC=0 test.c ../oprf.c ../utils.c -lsodium

tv2: test.c cfrg_oprf_test_vectors.h cfrg_oprf_test_vector_decl.h ../oprf.c ../utils.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g -o tv2 -DCFRG_TEST_VEC=1 -DCFRG_OPRF_TEST_VEC=1 -DTC=1 test.c ../oprf.c ../utils.c -lsodium

toprf: toprf.c 
	$(CC) $(CPPFLAGS) $(CFLAGS) -g -o toprf toprf.c ../toprf.c ../oprf.c $(EXTRA_SOURCES) -lsodium

dkg: ../dkg.c ../utils.c dkg.c ../dkg.c ../utils.c ../toprf.c ../oprf.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -g $(INCLUDES) -DUNIT_TEST -o dkg dkg.c ../dkg.c ../utils.c ../toprf.c ../oprf.c ../noise_xk/liboprf-noiseXK.a $(LDFLAGS) -lsodium

tp-dkg: ../tp-dkg.c tp-dkg.c ../tp-dkg.c ../utils.c ../toprf.c ../oprf.c ../dkg.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -D_DEFAULT_SOURCE -g -std=c11 $(INCLUDES) -DWITH_SODIUM -DUNITTEST -o tp-dkg tp-dkg.c ../tp-dkg.c ../utils.c ../toprf.c ../oprf.c ../dkg.c ../noise_xk/liboprf-noiseXK.a $(LDFLAGS) -lsodium

tp-dkg-corrupt: ../tp-dkg.c tp-dkg.c ../tp-dkg.c ../utils.c ../toprf.c ../oprf.c ../dkg.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -D_DEFAULT_SOURCE -g -std=c11 $(INCLUDES) -DWITH_SODIUM -DUNITTEST -DUNITTEST_CORRUPT -o tp-dkg-corrupt tp-dkg.c ../tp-dkg.c ../utils.c ../toprf.c ../oprf.c ../dkg.c ../noise_xk/liboprf-noiseXK.a $(LDFLAGS) -lsodium

stp-dkg: ../dkg-vss.c ../dkg.c ../stp-dkg.c stp-dkg.c ../stp-dkg.h ../mpmult.c ../utils.c ../toprf.c ../oprf.c ../dkg.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g $(INCLUDES) -DUNIT_TEST -o stp-dkg stp-dkg.c ../dkg-vss.c ../mpmult.c ../utils.c ../toprf.c ../stp-dkg.c ../oprf.c ../dkg.c ../noise_xk/liboprf-noiseXK.a $(LDFLAGS) -lsodium

stp-dkg-corrupt: ../dkg-vss.c ../dkg.c ../stp-dkg.c stp-dkg.c ../stp-dkg.h ../mpmult.c ../utils.c ../toprf.c ../oprf.c ../dkg.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g $(INCLUDES) -DUNIT_TEST -DUNITTEST_CORRUPT -o stp-dkg-corrupt stp-dkg.c ../dkg-vss.c ../mpmult.c ../utils.c ../toprf.c ../stp-dkg.c ../oprf.c ../dkg.c ../noise_xk/liboprf-noiseXK.a $(LDFLAGS) -lsodium

mpmult: ../mpmult.c mpmult.c ../utils.c ../toprf.c ../dkg-vss.c ../oprf.c ../dkg.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g $(INCLUDES) -DUNIT_TEST -o mpmult mpmult.c ../mpmult.c ../utils.c ../toprf.c ../dkg-vss.c ../oprf.c ../dkg.c ../noise_xk/liboprf-noiseXK.a -lsodium

update-poc: ../dkg-vss.c ../dkg.c update-poc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g $(INCLUDES) -DUNIT_TEST -o update-poc update-poc.c ../dkg-vss.c ../utils.c ../toprf.c ../noise_xk/liboprf-noiseXK.a -lsodium

ft-mult: ../dkg-vss.c ../dkg.c ft-mult.c ../toprf.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g $(INCLUDES) -DUNIT_TEST -o ft-mult ft-mult.c ../dkg-vss.c ../utils.c ../toprf.c ../noise_xk/liboprf-noiseXK.a -lsodium

toprf-update: ../dkg-vss.c ../dkg.c ../toprf-update.c toprf-update.c ../toprf-update.h ../mpmult.c ../oprf.c ../dkg.c $(EXTRA_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g $(INCLUDES) -DUNIT_TEST -o toprf-update toprf-update.c ../dkg-vss.c ../mpmult.c ../utils.c ../toprf.c ../toprf-update.c ../oprf.c ../dkg.c $(EXTRA_SOURCES) ../noise_xk/liboprf-noiseXK.a -lsodium

toprf-update-corrupt: ../dkg-vss.c ../dkg.c ../toprf-update.c toprf-update.c ../toprf-update.h ../mpmult.c ../utils.c ../oprf.c ../dkg.c $(EXTRA_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -g $(INCLUDES) -DUNIT_TEST -DUNITTEST_CORRUPT -o toprf-update-corrupt toprf-update.c ../dkg-vss.c ../mpmult.c ../utils.c ../toprf.c ../toprf-update.c  ../oprf.c ../dkg.c $(EXTRA_SOURCES) ../noise_xk/liboprf-noiseXK.a -lsodium

allocations: allocations.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -g -o allocations allocations.c -I.. -I../noise_xk/include -I../noise_xk/include/karmel/ -I../noise_xk/include/karmel/minimal -loprf -loprf-noiseXK

cfrg_oprf_test_vectors.h: testvecs2h.py
	./testvecs2h.py $@ >$@

cfrg_oprf_test_vector_decl.h: testvecs2h.py
	./testvecs2h.py $@ >$@

tests: all
	./dkg
	./tv1
	./tv2
	./toprf
	(ulimit -s 66000; ./tp-dkg 3 2)
	(ulimit -s 66000; ./tp-dkg-corrupt 3 2 || exit 0)
	(ulimit -s 1966000; ./stp-dkg 9 4)
	(ulimit -s 1966000; ./stp-dkg-corrupt 9 4 || exit 0)
	(ulimit -s 1966000; ./toprf-update 9 4)
	(ulimit -s 1966000; ./toprf-update-corrupt 9 4)
	./mpmult

clean:
	rm -f cfrg_oprf_test_vector_decl.h cfrg_oprf_test_vectors.h tv1 tv2 tp-dkg dkg toprf mpmult stp-dkg-corrupt stp-dkg update-poc toprf-update toprf-update-corrupt
