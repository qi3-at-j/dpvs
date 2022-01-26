
#VERSION=1.0.0

EXCLUDE_SRC_FILES=fib6_prefix.c ip6fs_cache.c ipfs_cache.c ipfs_ctl.c
SOURCE=$(filter-out $(EXCLUDE_SRC_FILES), $(wildcard ./*.c))
OBJ=$(patsubst %.c, %.o, $(SOURCE))
INCLUDES=-I./h

PKGCONF ?= pkg-config
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)

LIBS=
LIB_PATH=

DEBUG=-D_LITTLE_ENDIAN_BITFIELD -DBITS_PER_LONG=64
CFLAGS=-Wall -c -mssse3

TARGET=app  
CC=gcc  

$(TARGET): $(OBJ)
	@mkdir -p output/
	$(CC) $(OBJ) $(LIB_PATH) $(LIBS) -o output/$(TARGET) $(LDFLAGS)
	#$(CC) $(OBJ) $(LIB_PATH) $(LIBS) -o output/$(TARGET).$(VERSION)  

%.o: %.c  
	$(CC) $(INCLUDES) $(DEBUG) $(CFLAGS) $< -o $@  

.PHONY: clean  
clean:  
	rm -rf $(OBJ) output/