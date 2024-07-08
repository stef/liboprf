in/msg0: msg0
	./msg0 >in/msg0

msg0: msg0.c
	gcc -o msg0 msg0.c -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf

peer-start: peer-start.c ../../tp-dkg.c
	afl-clang-lto -std=c11 -o peer-start peer-start.c ../../tp-dkg.c -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK

step16: 
	afl-clang-lto -o step16 ../../tp-dkg.c -DUNITTEST -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf -loprf-noiseXK

fuzz-ps: peer-start
	afl-fuzz -i in -o out ./peer-start

fuzz: step16
	afl-fuzz -i in -o out ./step16
