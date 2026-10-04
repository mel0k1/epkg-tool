# Makefile for epkg-tools
#
#   make            build epkg + mkepkg
#   make test       unit tests + e2e (local mirror)
#   make test-tls   TLS smoke test against a real HTTPS server
#   make sample     rebuild sample-repo/
#   make clean
#
# Cross-compiling for your hobby OS:
#   make CC=i686-elf-gcc PORT=epk_port_youros.c
# (provide src/epk_port_youros.c implementing include/epk_port.h)

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2
CFLAGS  += -std=c99 -Wall -Wextra
INC      = -Iinclude -Isrc -Isrc/tls/bearssl/inc -Isrc/tls/bearssl/src

PORT    ?= epk_port_posix.c

# pthread is used by the POSIX big-stack runner (epk_bigstack_run)
ifeq ($(PORT),epk_port_posix.c)
CFLAGS  += -pthread
endif

BEAR    = $(shell ls src/tls/bearssl/src/*/*.c 2>/dev/null)

CORE    = src/epk_util.c \
	src/epk_sha256.c \
	src/epk_crc32.c \
	src/epk_inflate.c \
	src/epk_gzc.c \
	src/epk_tar.c \
	src/epk_json.c \
	src/epk_pkginfo.c \
	src/epk_url.c \
	src/epk_conf.c \
	src/epk_index.c \
	src/epk_deps.c \
	src/epk_db.c \
	src/epk_ed25519.c \
	src/epk_signify.c

TLS     = src/epk_tls.c

NET     = src/epk_http.c

ENGINE  = src/epk_install.c

all: epkg mkepkg epkg-key

epkg: src/main.c $(CORE) $(TLS) $(NET) $(ENGINE) src/$(PORT) $(BEAR)
	$(CC) $(CFLAGS) $(INC) -o $@ src/main.c $(CORE) $(TLS) $(NET) \
	$(ENGINE) src/$(PORT) $(BEAR)

KEYCORE = src/epk_util.c src/epk_sha256.c src/epk_ed25519.c src/epk_signify.c

epkg-key: tools/epkg_key.c $(KEYCORE) src/$(PORT)
	$(CC) $(CFLAGS) $(INC) -o $@ tools/epkg_key.c $(KEYCORE) src/$(PORT)

mkepkg: tools/mkepkg.c $(filter-out src/epk_conf.c src/epk_index.c \
	src/epk_db.c src/epk_deps.c src/epk_http.c src/epk_install.c \
	src/epk_ed25519.c src/epk_signify.c,$(CORE)) \
	src/$(PORT)
	$(CC) $(CFLAGS) $(INC) -o $@ tools/mkepkg.c \
	$(filter-out src/epk_conf.c src/epk_index.c src/epk_db.c \
	src/epk_deps.c src/epk_http.c src/epk_install.c \
	src/epk_ed25519.c src/epk_signify.c,$(CORE)) src/$(PORT)

# ---------------- tests ----------------

test: epkg mkepkg epkg-key
	./tests/run_tests.sh

test-ed: epkg-key
	$(CC) $(CFLAGS) $(INC) -o tests/t_ed25519 tests/t_ed25519.c \
	src/epk_ed25519.c src/epk_sha256.c
	./tests/t_ed25519

# TLS smoke test against a real HTTPS server (raw.githubusercontent.com)
test-tls:
	$(CC) $(CFLAGS) $(INC) -o tests/t_tls tests/t_tls.c \
	src/epk_util.c src/epk_url.c src/epk_http.c src/epk_tls.c \
	src/epk_sha256.c src/epk_crc32.c src/epk_inflate.c src/epk_json.c \
	src/$(PORT) $(BEAR)
	./tests/t_tls

# ---------------- helpers ----------------

sample: mkepkg epkg-key
	sh tools/build-sample.sh

clean:
	rm -f epkg mkepkg epkg-key tests/t_core tests/t_tls tests/t_ed25519
	rm -rf sample-repo/packages/*.epkg sample-repo/index.json \
	       sample-repo/index.sig sample-repo/demo.pub

.PHONY: all test test-ed test-tls sample clean
