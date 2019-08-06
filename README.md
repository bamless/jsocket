# jsocket
A straightforward socket library for the [J*](https://github.com/bamless/jstar) language.
This library is basically a direct wrapper of the C Berkeley socket API.

## Compatibility
For now the library is only compatible with POSIX systems. A Win32 port should not be difficult since the Winsock API is basically the same as the Berkeley one.

## Compilation and usage
For now the project uses a minimal Makefile to compile the shared library, a more general build solution will be used when Winscock support is added. The DESTDIR environment variable is used during the install target to copy the socket.bl and libsocket.so files to a suitable destination. This should be changed to a path present in the JSTARPATH environment variable, so that the interpreter can load the library (the default is /usr/local/lib/jstar).
