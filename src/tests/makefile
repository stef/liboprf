all: tv1 tv2 dkg tp-dkg

tv1: test.c cfrg_oprf_test_vectors.h cfrg_oprf_test_vector_decl.h
	gcc -Wall -g -o tv1 -DCFRG_TEST_VEC=1 -DCFRG_OPRF_TEST_VEC=1 -DTC=0 test.c ../oprf.c ../utils.c -lsodium

tv2: test.c cfrg_oprf_test_vectors.h cfrg_oprf_test_vector_decl.h
	gcc -Wall -g -o tv2 -DCFRG_TEST_VEC=1 -DCFRG_OPRF_TEST_VEC=1 -DTC=1 test.c ../oprf.c ../utils.c -lsodium

dkg: ../dkg.c ../toprf.c ../utils.c ../oprf.c dkg.c
	gcc -g -I.. -DUNIT_TEST -o dkg dkg.c ../dkg.c ../utils.c ../oprf.c ../toprf.c -lsodium

tp-dkg: ../tp-dkg.c tp-dkg.c
	gcc -g -std=c11 -I.. -I../noise_xk/include -I../noise_xk/include/karmel/ -I../noise_xk/include/karmel/minimal/ -DWITH_SODIUM -DUNITTEST -o tp-dkg tp-dkg.c ../tp-dkg.c ../utils.c -lsodium -loprf -loprf-noiseXK

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
	./tp-dkg || exit 0

clean:
	rm -f cfrg_oprf_test_vector_decl.h cfrg_oprf_test_vectors.h tv1 tv2 tp-dkg dkg
