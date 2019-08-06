DESTDIR=/usr/local/lib/blang

all: dir bin/libsocket.so

.PHONY: dir
dir:
	@mkdir -p bin

bin/libsocket.so: src/socket.c
	gcc -D_POSIX_C_SOURCE=200112 -Wall -Wextra -std=c99 -Wno-unused-parameter -o3 -s -shared -o $@ $< -Wl,-rpath /usr/local/lib -ljstar

.PHONY: install
install:
	mkdir -p $(DESTDIR)
	cp bin/libsocket.so src/socket.bl $(DESTDIR)

.PHONY: clean
clean:
	rm -rf bin
