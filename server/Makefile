# gmssl path
GM_LIBDIR = ../lib/gmssl/
GM_INCDIR = include/

CFLAGS := -I$(GM_INCDIR) \
          -L$(GM_LIBDIR)
STATIC_CFLAGS := -Wl,-rpath,$(GM_LIBDIR),-Bstatic
SHARED_CFLAGS := -Wl,-rpath,$(GM_LIBDIR),-Bdynamic

all: verify 


# ar -x ../lib/libcrypto.a 
verify:
	gcc -o csv-verify.o -c verify.c -I$(GM_INCDIR)
	ar -x ../lib/gmssl/libgmcrypto.a

	ar -rc libcsv-verify.a *.o
	rm -f *.o
# gcc -Wall $(CFLAGS) -fPIC -shared -o libcsv-verify.so verify.c -static-libgcc -Wl,-static -lgmcrypto $(SHARED_CFLAGS) -lpthread -ldl

test: verify
	g++ -o test test.cpp ../lib/libcrypto.a libcsv-verify.a -lpthread -ldl

test2:
	gcc $(CFLAGS) -o testsm2 testsm2.c -lgmcrypto -lpthread -ldl 

clean:
	rm -f verify test *.a