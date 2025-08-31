STEP?=6
N?=3
T?=2

#in/msg0: msg0
#	./msg0 >in/msg0
#
#msg0: msg0.c
#	gcc -o msg0 msg0.c -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf
#
#peer-start: peer-start.c ../../tp-dkg.c
#	afl-clang-lto -std=c11 -o peer-start peer-start.c ../../tp-dkg.c -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK
#
#fuzz-ps: peer-star
#	afl-fuzz -i in -o out ./peer-start

in/tc0: fuzz-dump
	./fuzz-dump $(N) $(T) $(STEP) in/tc0

in/tc0p: fuzz-dump-peer
	./fuzz-dump-peer $(N) $(T) $(STEP) in/tc0p

fuzz-dump: ../../tp-dkg.c ../tp-dkg.c
	gcc $(CPPFLAGS) $(CFLAGS) -g -o fuzz-dump ../../tp-dkg.c ../tp-dkg.c -DFUZZ_DUMP -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM $(LDFLAGS) -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer

fuzz-dump-peer: ../../tp-dkg.c ../tp-dkg.c
	gcc $(CPPFLAGS) $(CFLAGS) -g -o fuzz-dump-peer ../../tp-dkg.c ../tp-dkg.c -DFUZZ_DUMP -DFUZZ_PEER -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM $(LDFLAGS) -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer

fuzz-complog: ../../tp-dkg.c ../tp-dkg.c
	AFL_USE_ASAN=1 AFL_LLVM_CMPLOG=1 afl-clang-lto -o fuzz-complog ../../tp-dkg.c ../tp-dkg.c -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-complog-peer: ../../tp-dkg.c ../tp-dkg.c
	AFL_USE_ASAN=1 AFL_LLVM_CMPLOG=1 afl-clang-lto -o fuzz-complog-peer ../../tp-dkg.c ../tp-dkg.c -DFUZZ_PEER -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin-asan:  ../../tp-dkg.c ../tp-dkg.c
	AFL_USE_ASAN=1 afl-clang-lto -o fuzz-bin-asan ../../tp-dkg.c ../tp-dkg.c -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin-asan-peer:  ../../tp-dkg.c ../tp-dkg.c
	AFL_USE_ASAN=1 afl-clang-lto -o fuzz-bin-asan-peer ../../tp-dkg.c ../tp-dkg.c -DFUZZ_PEER -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin:  ../../tp-dkg.c ../tp-dkg.c
	afl-clang-lto -o fuzz-bin ../../tp-dkg.c ../tp-dkg.c -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin-peer:  ../../tp-dkg.c ../tp-dkg.c
	afl-clang-lto -o fuzz-bin-peer ../../tp-dkg.c ../tp-dkg.c -DFUZZ_PEER -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-asan: in/tc0 fuzz-bin fuzz-bin-asan fuzz-complog
	afl-fuzz -c ./fuzz-complog -i in -o out -- ./fuzz-bin-asan $(N) $(T) $(STEP)

fuzz-asan-peer: in/tc0 fuzz-bin-peer fuzz-bin-asan-peer fuzz-complog-peer
	afl-fuzz -c ./fuzz-complog-peer -i in -o out -- ./fuzz-bin-asan-peer $(N) $(T) $(STEP)

fuzz: in/tc0 fuzz-bin fuzz-bin-asan fuzz-complog
	afl-fuzz -c ./fuzz-complog -i in -o out -- ./fuzz-bin $(N) $(T) $(STEP)

fuzz-peer: in/tc0p fuzz-bin-peer fuzz-bin-asan-peer fuzz-complog-peer
	afl-fuzz -c ./fuzz-complog-peer -i in -o out -- ./fuzz-bin-peer $(N) $(T) $(STEP)

clean:
	rm -rf fuzz-complog fuzz-bin fuzz-dump in/* out
