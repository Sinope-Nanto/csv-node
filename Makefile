# gmssl path
GM_LIBDIR = /opt/gmssl/lib/
GM_INCDIR = /opt/gmssl/include/

# openssl path
OPENSSL_LIBDIR = lib/

# all: static_csv_sdk csv_httpd

CURL_CFLAGS := -I$(GM_INCDIR) \
          -L$(GM_LIBDIR)
CURL_STATIC_CFLAGS := -Wl,-rpath,$(GM_LIBDIR),-Bstatic
CURL_SHARED_CFLAGS := -Wl,-rpath,$(GM_LIBDIR),-Bdynamic

HTTPD_CFLAGS := -L$(OPENSSL_LIBDIR)
HTTPD_STATIC_CFLAGS := -Wl,-rpath,$(HTTPD_CFLAGS),-Bstatic
HTTPD_SHARED_CFLAGS := -Wl,-rpath,$(HTTPD_CFLAGS),-Bdynamic


static_csv_sdk:
	gcc -Wall $(CURL_CFLAGS) -c src/csv_sdk/*.c
	ar -r lib/libcsv.a *.o
	rm *.o

csv_httpd:
	gcc -o bin/csv_httpd src/*.cpp -lhv_static -L. lib/libssl.a -L. lib/libcrypto.a -lstdc++ -lpthread -Wl,-rpath,-Bstatic -ldl

csv_curl: static_csv_sdk
	gcc -Wall $(CURL_CFLAGS) -o bin/csv_curl src/*.c -L. lib/libcsv.a $(CURL_STATIC_CFLAGS) -lcrypto $(CURL_SHARED_CFLAGS) -lstdc++ -ldl