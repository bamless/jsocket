#include <blang.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
    struct sockaddr_un sun;
};

static int resolveHostName(int family, const char *hostname, void *buf) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags |= AI_CANONNAME;

    int err = getaddrinfo(hostname, NULL, &hints, &res);
    if(err) return err;

    if(res) {
        switch(family) {
        case AF_INET: {
            in_addr_t *ip = (in_addr_t*) buf;
            *ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *sockaddr = ((struct sockaddr_in6*)res->ai_addr);
            uint8_t **ip = (uint8_t**) buf;
            memcpy(*ip, sockaddr->sin6_addr.s6_addr, sizeof(sockaddr->sin6_addr.s6_addr));
            break;
        }
        }
    }

    return 0;
}

static bool fillSockaddr(BlangVM *vm, union sockaddr_union *sockaddr, int family, const char *addr, 
                         int port, socklen_t *len) 
{
    memset(sockaddr, 0, sizeof(*sockaddr));
    sockaddr->sa.sa_family = family;

    switch(family) {
    case AF_INET: {
        *len = sizeof(sockaddr->s4);
        sockaddr->s4.sin_port = htons(port);
        int err = inet_pton(AF_INET, addr, &sockaddr->s4.sin_addr.s_addr);
        if(err < 0) BL_RAISE(vm, "SocketExcpetion", strerror(errno));
        // not a valid ipv4, try hostname
        if(err == 0) {
            err = resolveHostName(AF_INET, addr, &sockaddr->s4.sin_addr.s_addr);
            if(err) BL_RAISE(vm, "SocketException", gai_strerror(err));
        }
        break;
    }
    case AF_INET6: {
        *len = sizeof(sockaddr->s6);
        sockaddr->s6.sin6_port = htons(port);
        int err = inet_pton(AF_INET6, addr, &sockaddr->s6.sin6_addr.s6_addr);
        if(err < 0) BL_RAISE(vm, "SocketExcpetion", strerror(errno));
        // not a valid ipv4, try hostname
        if(err == 0) {
            err = resolveHostName(AF_INET6, addr, &sockaddr->s6.sin6_addr.s6_addr);
            if(err) BL_RAISE(vm, "SocketException", gai_strerror(err));
        }
        break;
    }
    case AF_UNIX: {
        *len = sizeof(sockaddr->sun);
        strncpy(sockaddr->sun.sun_path, addr, sizeof(sockaddr->sun.sun_path) - 1);
        break;
    }
    default:
        BL_RAISE(vm, "TypeException", "Ivalid socket family: %d.", family);
        break;
    }
    
    return true;
}

static int readFlags(BlangVM *vm, int slot) {
    int flags = 0;

    blTupleGetLength(vm, slot);
    size_t length = blGetNumber(vm, -1);
    blPop(vm);

    for(size_t i = 0; i < length; i++) {
        blTupleGet(vm, i, slot);
        if(!blCheckInt(vm, -1, "flags")) return -1;
        flags |= (int)blGetNumber(vm, -1);
        blPop(vm);
    }
    return flags;
}

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

    socklen_t socklen;
    union sockaddr_union sockaddr;
    if(!fillSockaddr(vm, &sockaddr, family, blGetString(vm, 1), blGetNumber(vm, 2), &socklen)) {
        return false;
    }

    if(bind(sock, &sockaddr.sa, socklen)) {
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
    union sockaddr_union client;
    socklen_t clientLen = sizeof(client);
    if((clientSock = accept(sock, &client.sa, &clientLen)) < 0) {
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

    switch(client.sa.sa_family) {
    case AF_INET: {
        char buf[INET_ADDRSTRLEN];
        if(!inet_ntop(client.s4.sin_family, &client.s4.sin_addr.s_addr, buf, sizeof(buf))) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
        blPushString(vm, buf);
        break;
    }
    case AF_INET6: {
        char buf[INET6_ADDRSTRLEN];
        if(!inet_ntop(client.s6.sin6_family, &client.s6.sin6_addr.s6_addr, buf, sizeof(buf))) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
        blPushString(vm, buf);
        break;
    }
    case AF_UNIX:
        blPushString(vm, client.sun.sun_path);
        break;
    default: break;
    }

    blPushTuple(vm, 2);
    return true;
}

static bool Socket_send(BlangVM *vm) {
    if(!blCheckStr(vm, 1, "data")) return false;
    const char *buf = blGetString(vm, 1);
    size_t bufLen = blGetStringSz(vm, 1);
    int flags = readFlags(vm, 2);
    if(flags == -1) return false;

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    ssize_t sent;
    if((sent = send(sock, buf, bufLen, flags)) < 0) {
        if(errno == EAGAIN) {
            blPushNull(vm);
            return true;
        }
        BL_RAISE(vm, "So9cketException", strerror(errno));
    }

    blPushNumber(vm, sent);
    return true;
}

static bool Socket_recv(BlangVM *vm) {
    if(!blCheckInt(vm, 1, "size")) return false;
    if(blGetNumber(vm, 1) < 0) {
        BL_RAISE(vm, "TypeException", "Size must be >= 0.");
    }
    size_t size = blGetNumber(vm, 1);
    int flags = readFlags(vm, 2);
    if(flags == -1) return false;

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    BlBuffer buf;
    blBufferInitSz(vm, &buf, size);

    ssize_t received;
    if((received = recv(sock, buf.data, size, flags)) < 0) {
        if(errno == EWOULDBLOCK || errno == EAGAIN) {
            blBufferFree(&buf);
            blPushNull(vm);
            return true;
        }
        BL_RAISE(vm, "SocketException", strerror(errno));
    }
    buf.len += received;
    blBufferPush(&buf);
    return true;
}

static bool Socket_sendto(BlangVM *vm) {
    if(!blCheckStr(vm, 1, "addr") || !blCheckInt(vm, 2, "port") || !blCheckStr(vm, 3, "data")) {
        return false;
    }
    int flags = readFlags(vm, 4);
    if(flags == -1) return false;

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    blGetField(vm, 0, M_SOCKET_FAMILY);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FAMILY)) return false;
    int family = blGetNumber(vm, -1);

    socklen_t socklen;
    union sockaddr_union sockaddr;
    if(!fillSockaddr(vm, &sockaddr, family, blGetString(vm, 1), blGetNumber(vm, 2), &socklen)) {
        return false;
    }

    const char *data = blGetString(vm, 3);
    size_t dataLen = blGetStringSz(vm, 3); 

    ssize_t sent;
    if((sent = sendto(sock, data, dataLen, 0, &sockaddr.sa, socklen)) < 0) {
        BL_RAISE(vm, "SocketException", strerror(errno));
    }

    blPushNumber(vm, sent);
    return true;
}

static bool Socket_recvfrom(BlangVM *vm) {
    if(!blCheckInt(vm, 1, "size")) {
        return false;
    }
    size_t size = blGetNumber(vm, 1);
    int flags = readFlags(vm, 2);
    if(flags == -1) return false;

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);
    
    BlBuffer buf;
    blBufferInitSz(vm, &buf, size);

    union sockaddr_union sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    memset(&sockaddr, 0, sizeof(sockaddr));

    ssize_t received;
    if((received = recvfrom(sock, buf.data, size, 0, &sockaddr.sa, &socklen)) < 0) {
        if(errno == EWOULDBLOCK || errno == EAGAIN) {
            blBufferFree(&buf);
            blPushNull(vm);
            return true;
        }
        BL_RAISE(vm, "SocketException", strerror(errno));
    }
    buf.len += received;
    blBufferPush(&buf);

    switch(sockaddr.sa.sa_family) {
    case AF_INET: {
        char buf[INET_ADDRSTRLEN];
        if(!inet_ntop(sockaddr.s4.sin_family, &sockaddr.s4.sin_addr.s_addr, buf, sizeof(buf))) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
        blPushString(vm, buf);
        blPushNumber(vm, ntohs(sockaddr.s4.sin_port));
        blPushTuple(vm, 2);
        blPushTuple(vm, 2);
        return true;
    }
    case AF_INET6: {
        char buf[INET6_ADDRSTRLEN];
        if(!inet_ntop(sockaddr.s6.sin6_family, &sockaddr.s6.sin6_addr.s6_addr, buf, sizeof(buf))) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
        blPushString(vm, buf);
        blPushNumber(vm, ntohs(sockaddr.s6.sin6_port));
        blPushTuple(vm, 2);
        blPushTuple(vm, 2);
        return true;
    }
    case AF_UNIX:
        blPushString(vm, sockaddr.sun.sun_path);
        break;
    default: break;
    }

    blPushTuple(vm, 2);
    return true;
}

static bool Socket_connect(BlangVM *vm) {
    if(!blCheckStr(vm, 1, "addr") || !blCheckInt(vm, 2, "port")) {
        return false;
    }

    blGetField(vm, 0, M_SOCKET_FAMILY);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FAMILY)) return false;
    int family = blGetNumber(vm, -1);

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    socklen_t socklen;
    union sockaddr_union sockaddr;
    if(!fillSockaddr(vm, &sockaddr, family, blGetString(vm, 1), blGetNumber(vm, 2), &socklen)) {
        return false;
    }

    if(connect(sock, &sockaddr.sa, socklen) < 0) {
        BL_RAISE(vm, "SocketException", strerror(errno));
    }

    blPushNull(vm);
    return true;
}

static bool Socket_setTimeout(BlangVM *vm) {
    if(!blCheckInt(vm, 1, "ms")) {
        return false;
    }
    int ms = blGetNumber(vm, 1);

    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    struct timeval timeout = {0};
    timeout.tv_usec = ms * 1000;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void*) &timeout, sizeof(timeout)) < 0) {
        BL_RAISE(vm, "SocketException", strerror(errno));
    }

    blPushNull(vm);
    return true;    
}

static bool Socket_getTimeout(BlangVM *vm) {
    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    struct timeval timeout = {0};
    socklen_t timeLen = sizeof(timeout);
    if(getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void*) &timeout, &timeLen) < 0) {
        BL_RAISE(vm, "SocketException", strerror(errno));
    }
    blPushNumber(vm, timeout.tv_usec / 1000);
    return true;
}

static bool Socket_setBlocking(BlangVM *vm) {
    if(!blCheckBool(vm, 1, "block")) {
        return false;
    }
    bool block = blGetBoolean(vm, 1);
    
    blGetField(vm, 0, M_SOCKET_FD);
    if(!blCheckInt(vm, -1, "Socket."M_SOCKET_FD)) return false;
    int sock = blGetNumber(vm, -1);

    if(block) {
        if(fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK) < 0) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
    } else {
        if(fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0) {
            BL_RAISE(vm, "SocketException", strerror(errno));
        }
    }

    blPushNull(vm);
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

    blPushNumber(vm, MSG_PEEK);
    blSetGlobal(vm, NULL, "MSG_PEEK");
    blPop(vm);

    blPushNumber(vm, MSG_OOB);
    blSetGlobal(vm, NULL, "MSG_OOB");
    blPop(vm);

    blPushNumber(vm, MSG_WAITALL);
    blSetGlobal(vm, NULL, "MSG_WAITALL");
    blPop(vm);

    blPushNumber(vm, MSG_EOR);
    blSetGlobal(vm, NULL, "MSG_EOR");
    blPop(vm);

    blPushNumber(vm, MSG_OOB);
    blSetGlobal(vm, NULL, "MSG_OOB");
    blPop(vm);

    blPushNumber(vm, MSG_NOSIGNAL);
    blSetGlobal(vm, NULL, "MSG_NOSIGNAL");
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
    BL_REGMETH(Socket, sendto, &Socket_sendto)
    BL_REGMETH(Socket, recvfrom, &Socket_recvfrom)
    BL_REGMETH(Socket, connect, &Socket_connect)
    BL_REGMETH(Socket, setTimeout, &Socket_setTimeout)
    BL_REGMETH(Socket, getTimeout, &Socket_getTimeout)
    BL_REGMETH(Socket, setBlocking, &Socket_setBlocking)
    BL_REGMETH(Socket, close, &Socket_close)
    BL_REGFUNC(init, &init)
    BL_REGEND
};

BLANG_API BlNativeReg *bl_open_socket() {
    return registry;
}