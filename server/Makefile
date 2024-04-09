# gmssl path
GM_LIBDIR = ../lib/gmssl/
GM_INCDIR = include/

CFLAGS := -I$(GM_INCDIR) \
          -L$(GM_LIBDIR)
STATIC_CFLAGS := -Wl,-rpath,$(GM_LIBDIR),-Bstatic
SHARED_CFLAGS := -Wl,-rpath,$(GM_LIBDIR),-Bdynamic

all: verify

verify:
	gcc -Wall $(CFLAGS) -fPIC -shared -o libcsv-verify.so verify.c -static-libgcc -Wl,-static -lcrypto $(SHARED_CFLAGS) -lpthread -ldl

clean:
	rm -f verify