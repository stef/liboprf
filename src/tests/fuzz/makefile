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
	./fuzz-dump in/tc0

fuzz-dump: ../../tp-dkg.c ../tp-dkg.c
	gcc -g -o fuzz-dump ../../tp-dkg.c ../tp-dkg.c -DFUZZ_DUMP -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer

fuzz-complog: ../../tp-dkg.c ../tp-dkg.c
	AFL_USE_ASAN=1 AFL_LLVM_CMPLOG=1 afl-clang-lto -o fuzz-complog ../../tp-dkg.c ../tp-dkg.c -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz-bin:  ../../tp-dkg.c ../tp-dkg.c
	AFL_USE_ASAN=1 afl-clang-lto -o fuzz-bin ../../tp-dkg.c ../tp-dkg.c -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK -fno-omit-frame-pointer -fsanitize-memory-track-origins=2

fuzz: in/tc0 fuzz-bin fuzz-complog
	afl-fuzz -c ./fuzz-complog -i in -o out ./fuzz-bin

clean:
	rm -rf fuzz-complog fuzz-bin fuzz-dump in/tc0 out
