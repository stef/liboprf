all: tv1 tv2

tv1: test.c cfrg_test_vectors.h cfrg_test_vector_decl.h
	gcc -Wall -g -o tv1 -DCFRG_OPRF_TEST_VEC -DCFRG_TEST_VEC=1 -DTC=0 test.c ../oprf.c ../utils.c -lsodium

tv2: test.c cfrg_test_vectors.h cfrg_test_vector_decl.h
	gcc -Wall -g -o tv2 -DCFRG_OPRF_TEST_VEC -DCFRG_TEST_VEC=1 -DTC=1 test.c ../oprf.c ../utils.c -lsodium

cfrg_test_vectors.h: testvecs2h.py
	./testvecs2h.py $@ >$@

cfrg_test_vector_decl.h: testvecs2h.py
	./testvecs2h.py $@ >$@

tests: all
	./tv1
	./tv2

clean:
	rm -f cfrg_test_vector_decl.h cfrg_test_vectors.h tv1 tv2
