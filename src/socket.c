#include <blang.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

//class Socket

#define M_SOCKET_FD     "_fd"
#define M_SOCKET_TYPE   "type"
#define M_SOCKET_FAMILY "family"
#define M_SOCKET_PROTO  "proto"

static bool Socket_new(BlangVM *vm) {
    if(!blCheckInt(vm, 1, "family") || !blCheckInt(vm, 2, "type") || !blCheckInt(vm, 3, "proto")) {
        return false;
    }

    int sock;
    if(blIsNull(vm, 4)) {
        if((sock = socket(blGetNumber(vm, 1), blGetNumber(vm, 2), blGetNumber(vm, 3))) < 0) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
    } else {
        if(!blCheckInt(vm, 4, "fd")) return false;
        sock = blGetNumber(vm, 4);
    }

    blPushNumber(vm, sock);
    blSetField(vm, 0, M_SOCKET_FD);
    blPushValue(vm, 1);
    blSetField(vm, 0, M_SOCKET_FAMILY);
    blPushValue(vm, 2);
    blSetField(vm, 0, M_SOCKET_TYPE);
    blPushValue(vm, 3);
    blSetField(vm, 0, M_SOCKET_PROTO);
    
    blPushValue(vm, 0);
    return true;
}

static bool Socket_bind(BlangVM *vm) {
    if(!blCheckStr(vm, 1, "addr") || !blCheckInt(vm, 2, "port")) {
        return false;
    }

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    blGetField(vm, 0, M_SOCKET_FAMILY);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FAMILY)) return false;
    int family = blGetNumber(vm, -1);

    struct sockaddr_in sockaddr;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = family;
	sockaddr.sin_port = htons(blGetNumber(vm, 2));
    if(family == AF_INET || family == AF_INET6) {
        int res;
        if((res = inet_pton(family, blGetString(vm, 1), &sockaddr.sin_addr.s_addr)) < 0) {
            if(res == 0) BL_RAISE(vm, "SocketException", "Invalid IP address.");
            BL_RAISE(vm, "SocketExcpetion", strerror(errno));
        }
    } else if((sockaddr.sin_addr.s_addr = inet_addr(blGetString(vm, 1))) == 0) {
        BL_RAISE(vm, "SocketException", "Invalid address.");
    }

    if(bind(sock, (struct sockaddr *) &sockaddr, sizeof(sockaddr))) {
		BL_RAISE(vm, "SocketException", strerror(errno));
	}

    blPushNull(vm);
    return true;
}

static bool Socket_listen(BlangVM *vm) {
    if(!blCheckInt(vm, 1, "backlog")) return false;
    int backlog = blGetNumber(vm, 1);
    if(backlog < 0) backlog = 0;
    
    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    if(listen(sock, backlog)) {
        BL_RAISE(vm, "SocketException", strerror(errno));
    }

    blPushNull(vm);
    return true;
}

static bool Socket_accept(BlangVM *vm) {
    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);
    
    int clientSock;
    struct sockaddr_in client;
	socklen_t clientLen = sizeof(client);
    if((clientSock = accept(sock, (struct sockaddr *) &client, &clientLen)) < 0) {
        if(errno == EWOULDBLOCK || errno == EAGAIN) {
            blPushNull(vm);
            return true;
        } else {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
    }

    blGetGlobal(vm, NULL, "Socket");
    blGetField(vm, 0, M_SOCKET_FAMILY);
    blGetField(vm, 0, M_SOCKET_TYPE);
    blGetField(vm, 0, M_SOCKET_PROTO);
    blPushNumber(vm, clientSock);
    if(blCall(vm, 4) != VM_EVAL_SUCCSESS) return false;

    if(client.sin_family != AF_UNIX) {
        char buf[INET6_ADDRSTRLEN];
        if(inet_ntop(client.sin_family, &client.sin_addr.s_addr, buf, sizeof(buf)) == NULL) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
        blPushString(vm, buf);
        blPushTuple(vm, 2);
        return true;
    }

    return true;
}

static bool Socket_send(BlangVM *vm) {
    // TODO: allow flags?
    if(!blCheckStr(vm, 1, "data")) return false;
    const char *buf = blGetString(vm, 1);
    size_t bufLen = blGetStringSz(vm, 1);

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    ssize_t sent = 0;
    while((sent = send(sock, buf + sent, bufLen - sent, MSG_NOSIGNAL)) < (ssize_t) bufLen) {
        if(sent == -1) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
    }

    blPushNull(vm);
    return true;
}

static bool Socket_recv(BlangVM *vm) {
    // TODO: allow flags?
    if(!blCheckInt(vm, 1, "size")) return false;
    if(blGetNumber(vm, 1) < 0) {
        BL_RAISE(vm, "TypeException", "Size must be >= 0.");
    }
    size_t size = blGetNumber(vm, 1);

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    BlBuffer buf;
    blBufferInitSz(vm, &buf, size);

    ssize_t received;
    if((received = recv(sock, buf.data, size, 0)) < 0) {
        if(errno == EWOULDBLOCK || errno == EAGAIN) {
            blPushNull(vm);
            return true;
        }
        BL_RAISE(vm, "SocketException", strerror(errno));
    }
    buf.len += received;
    blBufferPush(&buf);
    return true;
}

static bool Socket_close(BlangVM *vm) {
    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);
    if(close(sock)) {
        BL_RAISE(vm, "SocketException", strerror(errno));
    }
    blPushNull(vm);
    return true;
}

// end

// Init constants 'n stuff
static bool init(BlangVM *vm) {
    blPushNumber(vm, AF_INET);
    blSetGlobal(vm, NULL, "AF_INET");
    blPop(vm);

    blPushNumber(vm, AF_INET6);
    blSetGlobal(vm, NULL, "AF_INET6");
    blPop(vm);

    blPushNumber(vm, AF_UNIX);
    blSetGlobal(vm, NULL, "AF_UNIX");
    blPop(vm);

    blPushNumber(vm, SOCK_STREAM);
    blSetGlobal(vm, NULL, "SOCK_STREAM");
    blPop(vm);

    blPushNumber(vm, SOCK_DGRAM);
    blSetGlobal(vm, NULL, "SOCK_DGRAM");
    blPop(vm);

    blPushNull(vm);
    return true;
}

// ---- Native function registry and native module initialization function ----

static BlNativeReg registry[] = {
    BL_REGMETH(Socket, new, &Socket_new)
    BL_REGMETH(Socket, bind, &Socket_bind)
    BL_REGMETH(Socket, listen, &Socket_listen)
    BL_REGMETH(Socket, accept, &Socket_accept)
    BL_REGMETH(Socket, send, &Socket_send)
    BL_REGMETH(Socket, recv, &Socket_recv)
    // TODO: add recvfrom
    // TODO: add connect
    BL_REGMETH(Socket, close, &Socket_close)
    BL_REGFUNC(init, &init)
    BL_REGEND
};

BLANG_API BlNativeReg *bl_open_socket() {
    return registry;
}