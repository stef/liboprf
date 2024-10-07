CFLAGS?= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
		   -fstack-protector-strong -fasynchronous-unwind-tables -fpic \
		   -ftrapv -D_GLIBCXX_ASSERTIONS \
		   -Wl,-z,defs -Wl,-z,relro \
		   -Wl,-z,noexecstack -Wl,-z,now -fsanitize=signed-integer-overflow \
		   -fsanitize-undefined-trap-on-error
CC?=gcc

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	CFLAGS+=-fcf-protection=full 
endif
ifeq ($(ARCH),parisc64)
else ifeq ($(ARCH),parisc64)
else
	CFLAGS+=-fstack-clash-protection
endif

all: tv1 tv2 dkg toprf tp-dkg tp-dkg-corrupt

tv1: test.c cfrg_oprf_test_vectors.h cfrg_oprf_test_vector_decl.h ../oprf.c ../utils.c
	$(CC) -Wall -g -o tv1 -DCFRG_TEST_VEC=1 -DCFRG_OPRF_TEST_VEC=1 -DTC=0 test.c ../oprf.c ../utils.c -lsodium

tv2: test.c cfrg_oprf_test_vectors.h cfrg_oprf_test_vector_decl.h ../oprf.c ../utils.c
	$(CC) -Wall -g -o tv2 -DCFRG_TEST_VEC=1 -DCFRG_OPRF_TEST_VEC=1 -DTC=1 test.c ../oprf.c ../utils.c -lsodium

toprf: toprf.c ../liboprf.a
	$(CC) -g -o toprf toprf.c ../liboprf.a $(EXTRA_SOURCES) -lsodium

dkg: ../dkg.c ../utils.c dkg.c ../dkg.c ../liboprf.a ../utils.c
	$(CC) $(CFLAGS) -g -I.. -DUNIT_TEST -o dkg dkg.c ../dkg.c ../utils.c ../liboprf.a -lsodium

tp-dkg: ../tp-dkg.c tp-dkg.c ../liboprf.a ../tp-dkg.c
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE -g -std=c11 -I.. -I../noise_xk/include -I../noise_xk/include/karmel/ -I../noise_xk/include/karmel/minimal/ -DWITH_SODIUM -DUNITTEST -o tp-dkg tp-dkg.c ../tp-dkg.c ../liboprf.a ../noise_xk/liboprf-noiseXK.a -lsodium

tp-dkg-corrupt: ../tp-dkg.c tp-dkg.c ../liboprf.a ../tp-dkg.c
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE -g -std=c11 -I.. -I../noise_xk/include -I../noise_xk/include/karmel/ -I../noise_xk/include/karmel/minimal/ -DWITH_SODIUM -DUNITTEST -DUNITTEST_CORRUPT -o tp-dkg-corrupt tp-dkg.c ../tp-dkg.c ../liboprf.a ../noise_xk/liboprf-noiseXK.a -lsodium

../liboprf.a:
	make -C .. liboprf.a

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

clean:
	rm -f cfrg_oprf_test_vector_decl.h cfrg_oprf_test_vectors.h tv1 tv2 tp-dkg dkg toprf
