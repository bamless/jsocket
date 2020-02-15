#include <jstar.h>
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
            struct sockaddr_in *sockaddr = (struct sockaddr_in*)res->ai_addr;
            in_addr_t *ip = (in_addr_t*) buf;
            *ip = sockaddr->sin_addr.s_addr;
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *sockaddr = (struct sockaddr_in6*)res->ai_addr;
            uint8_t *ip = (uint8_t*) buf;
            memcpy(ip, sockaddr->sin6_addr.s6_addr, sizeof(sockaddr->sin6_addr.s6_addr));
            break;
        }
        }
        freeaddrinfo(res);
    }

    return 0;
}

static bool fillSockaddr(JStarVM *vm, union sockaddr_union *sockaddr, int family, 
    const char *addr, int port, socklen_t *len) 
{
    memset(sockaddr, 0, sizeof(*sockaddr));
    sockaddr->sa.sa_family = family;

    switch(family) {
    case AF_INET: {
        *len = sizeof(sockaddr->s4);
        sockaddr->s4.sin_port = htons(port);
        int err = inet_pton(AF_INET, addr, &sockaddr->s4.sin_addr.s_addr);
        if(err < 0) JSR_RAISE(vm, "SocketExcpetion", strerror(errno));
        // not a valid ipv4, try hostname
        if(err == 0) {
            err = resolveHostName(AF_INET, addr, &sockaddr->s4.sin_addr.s_addr);
            if(err) JSR_RAISE(vm, "SocketException", gai_strerror(err));
        }
        break;
    }
    case AF_INET6: {
        *len = sizeof(sockaddr->s6);
        sockaddr->s6.sin6_port = htons(port);
        int err = inet_pton(AF_INET6, addr, &sockaddr->s6.sin6_addr.s6_addr);
        if(err < 0) JSR_RAISE(vm, "SocketExcpetion", strerror(errno));
        // not a valid ipv6, try hostname
        if(err == 0) {
            err = resolveHostName(AF_INET6, addr, &sockaddr->s6.sin6_addr.s6_addr);
            if(err) JSR_RAISE(vm, "SocketException", gai_strerror(err));
        }
        break;
    }
    case AF_UNIX: {
        *len = sizeof(sockaddr->sun);
        strncpy(sockaddr->sun.sun_path, addr, sizeof(sockaddr->sun.sun_path) - 1);
        break;
    }
    default:
        JSR_RAISE(vm, "TypeException", "Ivalid socket family: %d.", family);
        break;
    }
    
    return true;
}

static int readFlags(JStarVM *vm, int slot) {
    int flags = 0;
    size_t length =  jsrTupleGetLength(vm, slot);
    for(size_t i = 0; i < length; i++) {
        jsrTupleGet(vm, i, slot);
        if(!jsrCheckInt(vm, -1, "flags")) return -1;
        flags |= (int)jsrGetNumber(vm, -1);
        jsrPop(vm);
    }
    return flags;
}

//class Socket

#define M_SOCKET_FD     "__fd"
#define M_SOCKET_TYPE   "type"
#define M_SOCKET_FAMILY "family"
#define M_SOCKET_PROTO  "proto"

static bool Socket_new(JStarVM *vm) {
    JSR_CHECK(Int, 1, "family");
    JSR_CHECK(Int, 2, "type");
    JSR_CHECK(Int, 3, "proto");

    int sock;
    if(jsrIsNull(vm, 4)) {
        if((sock = socket(jsrGetNumber(vm, 1), jsrGetNumber(vm, 2), jsrGetNumber(vm, 3))) < 0) {
            JSR_RAISE(vm, "SocketException", strerror(errno));
        }
    } else {
        JSR_CHECK(Int, 4, "fd");
        sock = jsrGetNumber(vm, 4);
    }

    jsrPushNumber(vm, sock);
    jsrSetField(vm, 0, M_SOCKET_FD);
    jsrPushValue(vm, 1);
    jsrSetField(vm, 0, M_SOCKET_FAMILY);
    jsrPushValue(vm, 2);
    jsrSetField(vm, 0, M_SOCKET_TYPE);
    jsrPushValue(vm, 3);
    jsrSetField(vm, 0, M_SOCKET_PROTO);
    
    jsrPushValue(vm, 0);
    return true;
}

static bool Socket_bind(JStarVM *vm) {
    JSR_CHECK(String, 1, "addr");
    JSR_CHECK(Int, 2, "port");

    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    jsrGetField(vm, 0, M_SOCKET_FAMILY);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FAMILY);
    int family = jsrGetNumber(vm, -1);

    socklen_t socklen;
    union sockaddr_union sockaddr;
    if(!fillSockaddr(vm, &sockaddr, family, jsrGetString(vm, 1), jsrGetNumber(vm, 2), &socklen)) {
        return false;
    }

    if(bind(sock, &sockaddr.sa, socklen)) {
		JSR_RAISE(vm, "SocketException", strerror(errno));
    }

    jsrPushNull(vm);
    return true;
}

static bool Socket_listen(JStarVM *vm) {
    JSR_CHECK(Int, 1, "backlog");
    int backlog = jsrGetNumber(vm, 1);
    if(backlog < 0) backlog = 0;
    
    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    if(listen(sock, backlog)) {
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }

    jsrPushNull(vm);
    return true;
}

static bool Socket_accept(JStarVM *vm) {
    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);
    
    int clientSock;
    union sockaddr_union client;
    socklen_t clientLen = sizeof(client);
    if((clientSock = accept(sock, &client.sa, &clientLen)) < 0) {
        if(errno == EWOULDBLOCK || errno == EAGAIN) {
            jsrPushNull(vm);
            return true;
        } else {
            JSR_RAISE(vm, "SocketException", strerror(errno));
        }
    }

    jsrGetGlobal(vm, NULL, "Socket");
    jsrGetField(vm, 0, M_SOCKET_FAMILY);
    jsrGetField(vm, 0, M_SOCKET_TYPE);
    jsrGetField(vm, 0, M_SOCKET_PROTO);
    jsrPushNumber(vm, clientSock);
    if(jsrCall(vm, 4) != VM_EVAL_SUCCESS) return false;

    switch(client.sa.sa_family) {
    case AF_INET: {
        char buf[INET_ADDRSTRLEN];
        if(!inet_ntop(client.s4.sin_family, &client.s4.sin_addr.s_addr, buf, sizeof(buf))) {
            JSR_RAISE(vm, "SocketException", strerror(errno));
        }
        jsrPushString(vm, buf);
        break;
    }
    case AF_INET6: {
        char buf[INET6_ADDRSTRLEN];
        if(!inet_ntop(client.s6.sin6_family, &client.s6.sin6_addr.s6_addr, buf, sizeof(buf))) {
            JSR_RAISE(vm, "SocketException", strerror(errno));
        }
        jsrPushString(vm, buf);
        break;
    }
    case AF_UNIX:
        jsrPushString(vm, client.sun.sun_path);
        break;
    default: break;
    }

    jsrPushTuple(vm, 2);
    return true;
}

static bool Socket_send(JStarVM *vm) {
    JSR_CHECK(String, 1, "data");
    const char *buf = jsrGetString(vm, 1);
    size_t bufLen = jsrGetStringSz(vm, 1);

    int flags = readFlags(vm, 2);
    if(flags == -1) return false;

    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    ssize_t sent;
    if((sent = send(sock, buf, bufLen, flags)) < 0) {
        if(errno == EAGAIN) {
            jsrPushNull(vm);
            return true;
        }
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }

    jsrPushNumber(vm, sent);
    return true;
}

static bool Socket_recv(JStarVM *vm) {
    JSR_CHECK(Int, 1, "size");
    if(jsrGetNumber(vm, 1) < 0) {
        JSR_RAISE(vm, "TypeException", "Size must be >= 0.");
    }
    size_t size = jsrGetNumber(vm, 1);
    int flags = readFlags(vm, 2);
    if(flags == -1) return false;

    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    JStarBuffer buf;
    jsrBufferInitSz(vm, &buf, size);

    ssize_t received;
    if((received = recv(sock, buf.data, size, flags)) < 0) {
        if(errno == EWOULDBLOCK || errno == EAGAIN) {
            jsrBufferFree(&buf);
            jsrPushNull(vm);
            return true;
        }
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }
    buf.len += received;
    jsrBufferPush(&buf);
    return true;
}

static bool Socket_sendto(JStarVM *vm) {
    JSR_CHECK(String, 1, "addr");
    JSR_CHECK(Int, 2, "port");
    JSR_CHECK(String, 3, "data");

    int flags = readFlags(vm, 4);
    if(flags == -1) return false;

    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    jsrGetField(vm, 0, M_SOCKET_FAMILY);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FAMILY);
    int family = jsrGetNumber(vm, -1);

    socklen_t socklen;
    union sockaddr_union sockaddr;
    if(!fillSockaddr(vm, &sockaddr, family, jsrGetString(vm, 1), jsrGetNumber(vm, 2), &socklen)) {
        return false;
    }

    const char *data = jsrGetString(vm, 3);
    size_t dataLen = jsrGetStringSz(vm, 3); 

    ssize_t sent;
    if((sent = sendto(sock, data, dataLen, 0, &sockaddr.sa, socklen)) < 0) {
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }

    jsrPushNumber(vm, sent);
    return true;
}

static bool Socket_recvfrom(JStarVM *vm) {
    JSR_CHECK(Int, 1, "size");
    size_t size = jsrGetNumber(vm, 1);
    int flags = readFlags(vm, 2);
    if(flags == -1) return false;

    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);
    
    JStarBuffer buf;
    jsrBufferInitSz(vm, &buf, size);

    union sockaddr_union sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    memset(&sockaddr, 0, sizeof(sockaddr));

    ssize_t received;
    if((received = recvfrom(sock, buf.data, size, 0, &sockaddr.sa, &socklen)) < 0) {
        if(errno == EWOULDBLOCK || errno == EAGAIN) {
            jsrBufferFree(&buf);
            jsrPushNull(vm);
            return true;
        }
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }
    buf.len += received;
    jsrBufferPush(&buf);

    switch(sockaddr.sa.sa_family) {
    case AF_INET: {
        char buf[INET_ADDRSTRLEN];
        if(!inet_ntop(sockaddr.s4.sin_family, &sockaddr.s4.sin_addr.s_addr, buf, sizeof(buf))) {
            JSR_RAISE(vm, "SocketException", strerror(errno));
        }
        jsrPushString(vm, buf);
        jsrPushNumber(vm, ntohs(sockaddr.s4.sin_port));
        jsrPushTuple(vm, 2);
        jsrPushTuple(vm, 2);
        return true;
    }
    case AF_INET6: {
        char buf[INET6_ADDRSTRLEN];
        if(!inet_ntop(sockaddr.s6.sin6_family, &sockaddr.s6.sin6_addr.s6_addr, buf, sizeof(buf))) {
            JSR_RAISE(vm, "SocketException", strerror(errno));
        }
        jsrPushString(vm, buf);
        jsrPushNumber(vm, ntohs(sockaddr.s6.sin6_port));
        jsrPushTuple(vm, 2);
        jsrPushTuple(vm, 2);
        return true;
    }
    case AF_UNIX:
        jsrPushString(vm, sockaddr.sun.sun_path);
        break;
    default: break;
    }

    jsrPushTuple(vm, 2);
    return true;
}

static bool Socket_connect(JStarVM *vm) {
    JSR_CHECK(String, 1, "addr");
    JSR_CHECK(Int, 2, "port");

    jsrGetField(vm, 0, M_SOCKET_FAMILY);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FAMILY);
    int family = jsrGetNumber(vm, -1);

    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    socklen_t socklen;
    union sockaddr_union sockaddr;
    if(!fillSockaddr(vm, &sockaddr, family, jsrGetString(vm, 1), jsrGetNumber(vm, 2), &socklen)) {
        return false;
    }

    if(connect(sock, &sockaddr.sa, socklen) < 0) {
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }

    jsrPushNull(vm);
    return true;
}

static bool Socket_setTimeout(JStarVM *vm) {
    JSR_CHECK(Int, 1, "ms");
    int ms = jsrGetNumber(vm, 1);

    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    struct timeval timeout = {0};
    timeout.tv_usec = ms * 1000;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void*) &timeout, sizeof(timeout)) < 0) {
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }

    jsrPushNull(vm);
    return true;    
}

static bool Socket_getTimeout(JStarVM *vm) {
    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    struct timeval timeout = {0};
    socklen_t timeLen = sizeof(timeout);
    if(getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void*) &timeout, &timeLen) < 0) {
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }
    jsrPushNumber(vm, timeout.tv_usec / 1000);
    return true;
}

static bool Socket_setBlocking(JStarVM *vm) {
    JSR_CHECK(Boolean, 1, "block");
    bool block = jsrGetBoolean(vm, 1);
    
    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);

    if(block) {
        if(fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK) < 0) {
            JSR_RAISE(vm, "SocketException", strerror(errno));
        }
    } else {
        if(fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0) {
            JSR_RAISE(vm, "SocketException", strerror(errno));
        }
    }

    jsrPushNull(vm);
    return true;    
}

static bool Socket_close(JStarVM *vm) {
    jsrGetField(vm, 0, M_SOCKET_FD);
    JSR_CHECK(Int, -1, "Socket."M_SOCKET_FD);
    int sock = jsrGetNumber(vm, -1);
    if(close(sock)) {
        JSR_RAISE(vm, "SocketException", strerror(errno));
    }
    jsrPushNull(vm);
    return true;
}

// end

// Init constants 'n stuff
static bool init(JStarVM *vm) {
    jsrPushNumber(vm, AF_INET);
    jsrSetGlobal(vm, NULL, "AF_INET");
    jsrPop(vm);

    jsrPushNumber(vm, AF_INET6);
    jsrSetGlobal(vm, NULL, "AF_INET6");
    jsrPop(vm);

    jsrPushNumber(vm, AF_UNIX);
    jsrSetGlobal(vm, NULL, "AF_UNIX");
    jsrPop(vm);

    jsrPushNumber(vm, SOCK_STREAM);
    jsrSetGlobal(vm, NULL, "SOCK_STREAM");
    jsrPop(vm);

    jsrPushNumber(vm, SOCK_DGRAM);
    jsrSetGlobal(vm, NULL, "SOCK_DGRAM");
    jsrPop(vm);

    jsrPushNumber(vm, MSG_PEEK);
    jsrSetGlobal(vm, NULL, "MSG_PEEK");
    jsrPop(vm);

    jsrPushNumber(vm, MSG_OOB);
    jsrSetGlobal(vm, NULL, "MSG_OOB");
    jsrPop(vm);

    jsrPushNumber(vm, MSG_WAITALL);
    jsrSetGlobal(vm, NULL, "MSG_WAITALL");
    jsrPop(vm);

    jsrPushNumber(vm, MSG_EOR);
    jsrSetGlobal(vm, NULL, "MSG_EOR");
    jsrPop(vm);

    jsrPushNumber(vm, MSG_OOB);
    jsrSetGlobal(vm, NULL, "MSG_OOB");
    jsrPop(vm);

    jsrPushNumber(vm, MSG_NOSIGNAL);
    jsrSetGlobal(vm, NULL, "MSG_NOSIGNAL");
    jsrPop(vm);

    jsrPushNull(vm);
    return true;
}

// ---- Native function registry and native module initialization function ----

static JStarNativeReg registry[] = {
    JSR_REGMETH(Socket, new, &Socket_new)
    JSR_REGMETH(Socket, bind, &Socket_bind)
    JSR_REGMETH(Socket, listen, &Socket_listen)
    JSR_REGMETH(Socket, accept, &Socket_accept)
    JSR_REGMETH(Socket, send, &Socket_send)
    JSR_REGMETH(Socket, recv, &Socket_recv)
    JSR_REGMETH(Socket, sendto, &Socket_sendto)
    JSR_REGMETH(Socket, recvfrom, &Socket_recvfrom)
    JSR_REGMETH(Socket, connect, &Socket_connect)
    JSR_REGMETH(Socket, setTimeout, &Socket_setTimeout)
    JSR_REGMETH(Socket, getTimeout, &Socket_getTimeout)
    JSR_REGMETH(Socket, setBlocking, &Socket_setBlocking)
    JSR_REGMETH(Socket, close, &Socket_close)
    JSR_REGFUNC(init, &init)
    JSR_REGEND
};

JSTAR_API JStarNativeReg *jsr_open_socket() {
    return registry;
}
