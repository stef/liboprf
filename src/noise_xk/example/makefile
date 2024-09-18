LDFLAGS=-lsodium -loprf-noiseXK
SOURCES=xk-ex.c ../../utils.c

CFLAGS 	+= -I../.. -I../include -I ../include/karmel -I ../include/karmel/minimal \
				-Wall -Wextra -Werror -std=c11 -Wno-unused-variable \
				-Wno-unknown-warning-option -Wno-unused-but-set-variable \
				-Wno-unused-parameter -Wno-infinite-recursion -fPIC \
				-g -fwrapv -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM \
				-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
				-fasynchronous-unwind-tables -fpic -Werror=format-security \
				-Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro \
				-ftrapv -Wl,-z,noexecstack

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	CFLAGS+=-fcf-protection=full 
endif
ifeq ($(ARCH),parisc64)
else ifeq ($(ARCH),parisc64)
else
	CFLAGS+=-fstack-clash-protection
endif

all: xk-ex

xk-ex: $(SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -L..

AR ?= ar

test: xk-ex
	LD_LIBRARY_PATH=.. ./xk-ex

clean:
	rm -rf *.o xk-ex
