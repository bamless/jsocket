# jsocket
A straightforward socket library for the [J*](https://github.com/bamless/jstar) language.
This library is basically a direct wrapper of the C Berkeley socket API.

## Compatibility
For now the library is only compatible with POSIX systems. A Win32 port should not be difficult 
since the Winsock API is basically the same as the Berkeley one.

## Compilation and usage
The project uses cmake to compile and install  the shared library and associated J* source file.
Simply enter this into the command line:

```
mkdir build; cd build; cmake ../; make -j; sudo make install
```

The generated library and J* file will be installed by default in `/usr/local/lib/jstar`.

To use the library from the `jstar` command line interface you should add this path to an 
environment variable called `JSTARPATH`, by editing your .profile, /etc/profile or .bashrc file and
adding this line:

```
export JSTARPATH=/usr/local/lib/jstar
```

Once you've done that, you can start using the library by simply importing it:

```lua
import socket

var s = socket.connect('google.it', 80)
```
