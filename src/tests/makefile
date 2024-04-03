all: tv1 tv2 dkg

tv1: test.c cfrg_oprf_test_vectors.h cfrg_oprf_test_vector_decl.h
	gcc -Wall -g -o tv1 -DCFRG_TEST_VEC=1 -DCFRG_OPRF_TEST_VEC=1 -DTC=0 test.c ../oprf.c ../utils.c -lsodium

tv2: test.c cfrg_oprf_test_vectors.h cfrg_oprf_test_vector_decl.h
	gcc -Wall -g -o tv2 -DCFRG_TEST_VEC=1 -DCFRG_OPRF_TEST_VEC=1 -DTC=1 test.c ../oprf.c ../utils.c -lsodium

dkg: ../dkg.c ../utils.c ../liboprf.a
	gcc -g -I.. -DUNIT_TEST -o dkg dkg.c ../dkg.c ../utils.c ../liboprf.a -lsodium

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

clean:
	rm -f cfrg_oprf_test_vector_decl.h cfrg_oprf_test_vectors.h tv1 tv2
