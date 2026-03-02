CC = gcc
CFLAGS = -O3 -Wall -fPIC -shared
LIB_DIR = lib

all: $(LIB_DIR)/libntt.so $(LIB_DIR)/libkeccak.so

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(LIB_DIR)/libntt.so: ntt.c poly.c | $(LIB_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(LIB_DIR)/libkeccak.so: keccak.c | $(LIB_DIR)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(LIB_DIR)
