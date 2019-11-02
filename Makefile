DESTDIR=/usr/local/lib/jstar

all: dir bin/libsocket.so

.PHONY: dir
dir:
	@mkdir -p bin

bin/libsocket.so: src/socket.c
	gcc -D_POSIX_C_SOURCE=200112 -Wall -Wextra -std=c99 -Wno-unused-parameter -O3 -s -shared -o $@ $< -Wl,-rpath /usr/local/lib -ljstar

.PHONY: install
install:
	mkdir -p $(DESTDIR)
	cp bin/libsocket.so src/socket.jsr $(DESTDIR)

.PHONY: clean
clean:
	rm -rf bin
