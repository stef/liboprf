STEP?=3
N?=9
T?=4

includes=-I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal
defines=-D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -DUNIT_TEST -DUNITTEST_CORRUPT
libs=-lsodium -loprf -loprf-noiseXK
src=../../dkg-vss.c ../../dkg.c ../../toprf-update.c ../toprf-update.c ../../mpmult.c ../../utils.c ../../toprf.c

SODIUM_NEWER_THAN_1_0_18 := $(shell pkgconf --atleast-version=1.0.19 libsodium; echo $$?)
ifeq ($(SODIUM_NEWER_THAN_1_0_18),1)
   includes+= -I../../aux_
   src+=../../aux_/kdf_hkdf_sha256.c
else
   defines+= -DHAVE_SODIUM_HKDF=1
endif

in/tc0: fuzz-dump
	./fuzz-dump $(N) $(T) $(STEP) in/tc0

in/tc0p: fuzz-dump-peer
	./fuzz-dump-peer $(N) $(T) $(STEP) in/tc0p

fuzz-dump: $(src)
	gcc $(CPPFLAGS) $(CFLAGS) -g -o $@ $^ -DFUZZ_DUMP -DUNITTEST $(includes) $(defines) $(LDFLAGS) $(libs) -fno-omit-frame-pointer

fuzz-dump-peer: $(src)
	gcc $(CPPFLAGS) $(CFLAGS) -g -o $@ $^ -DFUZZ_DUMP -DFUZZ_PEER -DUNITTEST $(includes) $(defines) $(LDFLAGS) $(libs) -fno-omit-frame-pointer

fuzz-complog: $(src)
	AFL_USE_ASAN=1 AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -march=native -o $@ $^ -DUNITTEST $(includes) $(defines) $(libs) -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-complog-peer: $(src)
	AFL_USE_ASAN=1 AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -march=native -o $@ $^ -DFUZZ_PEER -DUNITTEST $(includes) $(defines) $(libs) -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin-asan:  $(src)
	AFL_USE_ASAN=1 afl-clang-lto -O2 -march=native -o $@ $^ -DUNITTEST $(includes) $(defines) $(libs) -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin-asan-peer:  $(src)
	AFL_USE_ASAN=1 afl-clang-lto -O2 -march=native -o $@ $^ -DFUZZ_PEER -DUNITTEST $(includes) $(defines) $(libs) -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin:  $(src)
	afl-clang-lto -o $@ $^ -DUNITTEST $(includes) $(defines) $(libs) -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin-peer:  $(src)
	afl-clang-lto -o $@ $^ -DFUZZ_PEER -DUNITTEST $(includes) $(defines) $(libs) -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-asan: in/tc0 fuzz-bin fuzz-bin-asan fuzz-complog
	afl-fuzz -c ./fuzz-complog -i in -o out -- ./fuzz-bin-asan $(N) $(T) $(STEP)

fuzz-asan-peer: in/tc0p fuzz-bin-peer fuzz-bin-asan-peer fuzz-complog-peer
	afl-fuzz -c ./fuzz-complog-peer -i in -o out -- ./fuzz-bin-asan-peer $(N) $(T) $(STEP)

fuzz: in/tc0 fuzz-bin fuzz-bin-asan fuzz-complog
	afl-fuzz -c ./fuzz-complog -i in -o out -- ./fuzz-bin $(N) $(T) $(STEP)

fuzz-peer: in/tc0p fuzz-bin-peer fuzz-bin-asan-peer fuzz-complog-peer
	afl-fuzz -c ./fuzz-complog-peer -i in -o out -- ./fuzz-bin-peer $(N) $(T) $(STEP)

clean:
	rm -rf fuzz-complog fuzz-bin fuzz-dump in/* out fuzz-bin-asan-peer  fuzz-bin-peer  fuzz-complog-peer  fuzz-dump-peer
