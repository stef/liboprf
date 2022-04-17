
toprf: oprf.c toprf.c main.c aux/kdf_hkdf_sha512.c sss/libsss.a
	gcc -Isss -o toprf oprf.c toprf.c main.c aux/kdf_hkdf_sha512.c sss/libsss.a -lsodium

sss/libsss.a:
	cd sss; make
