DESTDIR=/usr/local/lib/blang

all: dir bin/libsocket.so

.PHONY: dir
dir:
	@mkdir -p bin

bin/libsocket.so: src/socket.c
	gcc -Wall -Wextra -std=c99 -Wno-unused-parameter -shared -o $@ $< -Wl,-rpath /usr/local/lib -lblang

.PHONY: install
install:
	cp bin/libsocket.so src/socket.bl $(DESTDIR)

.PHONY: clean
clean:
	rm -rf bin
