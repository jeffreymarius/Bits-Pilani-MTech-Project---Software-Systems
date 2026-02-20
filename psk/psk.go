// project/psk/psk.go
package psk

/*
#cgo pkg-config: openssl
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

static int set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}
// IMPORTANT: declare the Go-exported functions with exact non-const
// signatures to avoid conflicting-type errors with the generated _cgo_export.h.
extern unsigned int go_psk_client_cb(void *ssl_ptr, char *hint, char *identity, unsigned int maxiden, unsigned char *psk, unsigned int maxpsk);
extern unsigned int go_psk_server_cb(void *ssl_ptr, char *identity, unsigned char *psk, unsigned int maxpsk);

// C wrapper that OpenSSL expects (uses const char* for hint/identity).
static unsigned int c_psk_client_cb(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len) {
    // cast away const to match go_psk_client_cb signature (Go exports use non-const)
    return go_psk_client_cb((void*)ssl, (char*)hint, identity, max_identity_len, psk, max_psk_len);
}

static unsigned int c_psk_server_cb(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len) {
    return go_psk_server_cb((void*)ssl, (char*)identity, psk, max_psk_len);
}

// add near other static functions in the C block

static int alpn_select_cb(SSL *ssl,
                          const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen,
                          void *arg)
{
    const unsigned char server_protos[] = { 0x02, 'h', '2' };
    unsigned int server_len = sizeof(server_protos);

    fprintf(stderr, "[psk] Setting h2 proto\n");
    unsigned char *chosen = NULL;
    unsigned char chosen_len = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    int rv = SSL_select_next_proto(&chosen, &chosen_len,
                                   server_protos, server_len,
                                   in, inlen);
    if (rv == OPENSSL_NPN_NEGOTIATED) {
        *out = chosen;
        *outlen = chosen_len;
        return SSL_TLSEXT_ERR_OK;
    }
#endif
    return SSL_TLSEXT_ERR_NOACK;
}

static int get_errno() {
    return errno;
}

static int openssl_init() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
    return 0;
}


static FILE *keylog_file = NULL;

static void keylog_callback(const SSL *ssl, const char *line) {
    if (!keylog_file) return;
    fprintf(keylog_file, "%s\n", line);
    fflush(keylog_file);
}

static SSL_CTX* create_psk_ctx() {
    const SSL_METHOD *method = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;

    // Restrict to TLS1.3 only
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Register the wrapper callbacks (which call into Go)
    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_psk_client_callback(ctx, c_psk_client_cb);
    SSL_CTX_set_psk_server_callback(ctx, c_psk_server_cb);
    const char *path = getenv("SSLKEYLOGFILE");
    if (path) {
        keylog_file = fopen(path, "a");
        if (keylog_file) {
            SSL_CTX_set_keylog_callback(ctx, keylog_callback);
            fprintf(stderr, "[psk] Keylog file enabled: %s\n", path);
        } else {
            fprintf(stderr, "[psk] Failed to open keylog file: %s\n", path);
        }
    }


    // Set TLS1.3 ciphersuites (OpenSSL 1.1.1+)
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    // In case TLS1.2 fallback is used anywhere, set cipher list (optional)
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

    // Advertise ALPN "h2" for HTTP/2 (gRPC)
    unsigned char alpn_protos[] = { 0x02, 'h', '2' };
    SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos));
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

    return ctx;
}

// small helper for accept wrapper (unused directly from Go here, but kept)
static int accept_fd(int listen_fd) {
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int fd = accept(listen_fd, (struct sockaddr*)&sa, &len);
    return fd;
}

static char* geti_ssl_errors() {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;

    ERR_print_errors(bio);

    char *buf;
    long len = BIO_get_mem_data(bio, &buf);
    char *ret = (char*)malloc(len + 1);
    if (ret) {
        memcpy(ret, buf, len);
        ret[len] = '\0';
    }
    BIO_free(bio);
    return ret;
}
*/
import "C"

import (
    "errors"
    "fmt"
    "net"
    "os"
    "sync"
    "time"
    "unsafe"
)

// DLKeyGen must be set by user code (server and client) before making connections.
// Example (in main package):
//    psk.DLKeyGen = func() []byte { return []byte("0123456789abcdef0123456789abcdef") }
var DLKeyGen func() []byte

var opensslOnce sync.Once

func opensslInit() {
    opensslOnce.Do(func() {
        C.openssl_init()
    })
}

//export go_psk_client_cb
func go_psk_client_cb(ssl_ptr unsafe.Pointer, hint *C.char, identity *C.char, maxiden C.uint, pskBuf *C.uchar, maxpsk C.uint) C.uint {
    if DLKeyGen == nil {
        fmt.Println("[psk] go_psk_client_cb: DLKeyGen is nil")
        return 0
    }
    var hintStr string
    if hint != nil {
        hintStr = C.GoString(hint)
    }

    key := DLKeyGen()
    if key == nil || len(key) == 0 {
        fmt.Println("[psk] go_psk_client_cb: DLKeyGen returned empty key")
        return 0
    }

    identityStr := "client-identity"
    // write identity (ensure fits)
    maxid := int(maxiden)
    idlen := len(identityStr)
    if idlen+1 > maxid {
        idlen = maxid - 1
    }
    cid := C.CString(identityStr)
    C.memcpy(unsafe.Pointer(identity), unsafe.Pointer(cid), C.size_t(idlen))
    C.free(unsafe.Pointer(cid))


    ptr := uintptr(unsafe.Pointer(identity)) + uintptr(idlen)
    *(*C.char)(unsafe.Pointer(ptr)) = 0

    // copy PSK into buffer
    keylen := len(key)
    if keylen > int(maxpsk) {
        keylen = int(maxpsk)
    }
    if keylen > 0 {
        C.memcpy(unsafe.Pointer(pskBuf), unsafe.Pointer(&key[0]), C.size_t(keylen))
    }


    fmt.Printf("Key:%v\n",key)
    fmt.Printf("[psk] client_cb invoked: hint=%q identity=%s returned_keylen=%d\n", hintStr, identityStr, keylen)
    return C.uint(keylen)
}

//export go_psk_server_cb
func go_psk_server_cb(ssl_ptr unsafe.Pointer, identity *C.char, pskBuf *C.uchar, maxpsk C.uint) C.uint {
    if DLKeyGen == nil {
        fmt.Println("[psk] go_psk_server_cb: DLKeyGen is nil")
        return 0
    }
    var idStr string
    if identity != nil {
        idStr = C.GoString(identity)
    }
    key := DLKeyGen()
    if key == nil || len(key) == 0 {
        fmt.Println("[psk] go_psk_server_cb: DLKeyGen returned empty key")
        return 0
    }
    keylen := len(key)
    if keylen > int(maxpsk) {
        fmt.Printf("[psk] go_psk_server_cb: key too long (%d > %d)\n", keylen, int(maxpsk))
        return 0
    }
    fmt.Printf("Key:%v\n",key)
    C.memcpy(unsafe.Pointer(pskBuf), unsafe.Pointer(&key[0]), C.size_t(keylen))
    fmt.Printf("[psk] server_cb invoked: client_identity=%s returned_keylen=%d\n", idStr, keylen)
    return C.uint(keylen)
}

// OpenSSLListener wraps a TCP listener and performs SSL_accept per connection.
type OpenSSLListener struct {
    ln     net.Listener
    ctx    *C.SSL_CTX
    closed bool
    mu     sync.Mutex
}

// CreateOpenSSLListener creates an OpenSSL-based listener.
// If useCert==true, it will load certFile/keyFile into ctx (optional).
func CreateOpenSSLListener(addr string, useCert bool, certFile, keyFile string) (*OpenSSLListener, error) {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from SSL_read panic:", r)
        }
    }()
	
    opensslInit()

    ln, err := net.Listen("tcp", addr)
    if err != nil {
        return nil, err
    }

    ctx := C.create_psk_ctx()
    if ctx == nil {
        ln.Close()
        return nil, errors.New("create_psk_ctx failed")
    }

    if useCert {
        ccert := C.CString(certFile)
        ckey := C.CString(keyFile)
        defer C.free(unsafe.Pointer(ccert))
        defer C.free(unsafe.Pointer(ckey))
        if C.SSL_CTX_use_certificate_file(ctx, ccert, C.SSL_FILETYPE_PEM) != 1 {
            ln.Close()
            C.SSL_CTX_free(ctx)
            return nil, errors.New("SSL_CTX_use_certificate_file failed")
        }
        if C.SSL_CTX_use_PrivateKey_file(ctx, ckey, C.SSL_FILETYPE_PEM) != 1 {
            ln.Close()
            C.SSL_CTX_free(ctx)
            return nil, errors.New("SSL_CTX_use_PrivateKey_file failed")
        }
    }

    fmt.Println("[psk] OpenSSL listener created, addr=", addr)
    return &OpenSSLListener{ln: ln, ctx: ctx}, nil
}

func (l *OpenSSLListener) Accept() (net.Conn, error) {
    rawConn, err := l.ln.Accept()
    if err != nil {
        return nil, err
    }

    tcpConn := rawConn.(*net.TCPConn)
    /*
    f, err := tcpConn.File()
    if err != nil {
        rawConn.Close()
        return nil, err
    }
    fd := C.int(f.Fd())
    f.Close()
*/
raw, err := tcpConn.SyscallConn()
if err != nil {
    rawConn.Close()
    return nil, err
}
var fd C.int
err = raw.Control(func(s uintptr) {
	fd = C.int(s)
})
if err != nil {
    rawConn.Close()
    return nil, err
}
C.set_blocking(fd)

    ssl := C.SSL_new(l.ctx)
    if ssl == nil {
        rawConn.Close()
        return nil, errors.New("SSL_new failed")
    }

    if C.SSL_set_fd(ssl, fd) != 1 {
        rawConn.Close()
        C.SSL_free(ssl)
        return nil, errors.New("SSL_set_fd failed")
    }


    ret := C.SSL_accept(ssl)
    if ret != 1 {
    sslErr := int(C.SSL_get_error(ssl, C.int(ret)))

    // Get full OpenSSL error queue
    cstr := C.geti_ssl_errors()
    var errStr string
    if cstr != nil {
        errStr = C.GoString(cstr)
        C.free(unsafe.Pointer(cstr))
    }

    fmt.Printf("%v\n",C.GoString(C.strerror(C.get_errno())))
    msg := fmt.Sprintf("SSL_accept failed (ret=%d ssl_err=%d): %s", int(ret), sslErr, errStr)
    fmt.Println("[psk] OpenSSL accept error:", msg)

    rawConn.Close()
    C.SSL_free(ssl)
    fmt.Errorf(msg)
    return nil, fmt.Errorf(msg)	  
    }

    conn := &OpenSSLConn{ssl: ssl, fd: int(fd), raw: rawConn}
    return conn, nil
}

func (l *OpenSSLListener) Close() error {
    l.mu.Lock()
    defer l.mu.Unlock()
    if l.closed {
        return nil
    }
    l.closed = true
    if l.ln != nil {
        l.ln.Close()
    }
    if l.ctx != nil {
        C.SSL_CTX_free(l.ctx)
    }
    return nil
}

func (l *OpenSSLListener) Addr() net.Addr { return l.ln.Addr() }

// OpenSSLConn implements net.Conn backed by OpenSSL SSL object
type OpenSSLConn struct {
    ssl *C.SSL
    fd  int
    raw net.Conn
    mu  sync.Mutex
}

func (c *OpenSSLConn) Read(b []byte) (int, error) {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from SSL_read panic:", r)
        }
    }()


    if c.ssl == nil {
        return 0, errors.New("ssl closed")
    }
    c.mu.Lock()
    n := C.SSL_read(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
    c.mu.Unlock()
    if n <= 0 {
        errCode := C.SSL_get_error(c.ssl, C.int(n))
        if errCode == C.SSL_ERROR_ZERO_RETURN {
            return 0, os.ErrClosed
        }
        return 0, fmt.Errorf("SSL_read error %d", int(errCode))
    }
    return int(n), nil
}

func (c *OpenSSLConn) Write(b []byte) (int, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("⚠️ Recovered from SSL_write panic:", r)
		}
	}()

    if c.ssl == nil {
        return 0, errors.New("ssl closed")
    }
    n := C.SSL_write(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
    if n <= 0 {
        errCode := C.SSL_get_error(c.ssl, C.int(n))
        return 0, fmt.Errorf("SSL_write error %d", int(errCode))
    }
    return int(n), nil
}

func (c *OpenSSLConn) Close() error {

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("⚠️ Recovered from SSL_close panic:", r)
		}
	}()

    if c.ssl != nil {
        C.SSL_shutdown(c.ssl)
        C.SSL_free(c.ssl)
        c.ssl = nil
    }
    if c.raw != nil {
        return c.raw.Close()
    }
    return nil
}

func (c *OpenSSLConn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *OpenSSLConn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }
func (c *OpenSSLConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *OpenSSLConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *OpenSSLConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// OpenSSLDial - connect TCP then perform SSL_connect (PSK client)
func OpenSSLDial(addr string, useCert bool, certFile, keyFile string) (net.Conn, error) {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from SSL_read panic:", r)
        }
    }()
	
    opensslInit()

    tcpConn, err := net.DialTimeout("tcp", addr, time.Second * 10)
    if err != nil {
        return nil, err
    }

    ctx := C.create_psk_ctx()
    if ctx == nil {
        tcpConn.Close()
        return nil, errors.New("create_psk_ctx failed")
    }

    if useCert {
        ccert := C.CString(certFile)
        ckey := C.CString(keyFile)
        defer C.free(unsafe.Pointer(ccert))
        defer C.free(unsafe.Pointer(ckey))
        if C.SSL_CTX_use_certificate_file(ctx, ccert, C.SSL_FILETYPE_PEM) != 1 {
            tcpConn.Close()
            C.SSL_CTX_free(ctx)
            return nil, errors.New("client cert load failed")
        }
        if C.SSL_CTX_use_PrivateKey_file(ctx, ckey, C.SSL_FILETYPE_PEM) != 1 {
            tcpConn.Close()
            C.SSL_CTX_free(ctx)
            return nil, errors.New("client key load failed")
        }
    }

    tcp := tcpConn.(*net.TCPConn)
    /*
    f, err := tcp.File()
    if err != nil {
        tcpConn.Close()
        C.SSL_CTX_free(ctx)
        return nil, err
    }
    fd := C.int(f.Fd())
    f.Close()
*/
raw, err := tcp.SyscallConn()
if err != nil {
    tcpConn.Close()
    C.SSL_CTX_free(ctx)
    return nil, err
}

var fd C.int
err = raw.Control(func(s uintptr) {
    fd = C.int(s)
})
if err != nil {
    tcpConn.Close()
    C.SSL_CTX_free(ctx)
    return nil, err
}
C.set_blocking(fd)
    ssl := C.SSL_new(ctx)
    if ssl == nil {
        tcpConn.Close()
        C.SSL_CTX_free(ctx)
        return nil, errors.New("SSL_new failed")
    }

    if C.SSL_set_fd(ssl, fd) != 1 {
        tcpConn.Close()
        C.SSL_free(ssl)
        C.SSL_CTX_free(ctx)
        return nil, errors.New("SSL_set_fd failed")
    }

    ret := C.SSL_connect(ssl)
    if ret != 1 {
        // collect OpenSSL error queue
        var msgs []string
        for {
            errnum := C.ERR_get_error()
            if errnum == 0 {
                break
            }
            cstr := C.ERR_error_string(errnum, nil)
            if cstr != nil {
                msgs = append(msgs, C.GoString(cstr))
            }
        }
        sslErr := int(C.SSL_get_error(ssl, C.int(ret)))
        msg := fmt.Sprintf("SSL_connect failed (ret=%d ssl_err=%d)", int(ret), sslErr)
        if len(msgs) > 0 {
            msg = msg + ": " + msgs[0]
            for i := 1; i < len(msgs); i++ {
                msg = msg + " | " + msgs[i]
            }
        }
        tcpConn.Close()
        C.SSL_free(ssl)
        C.SSL_CTX_free(ctx)
        return nil, errors.New(msg)
    }

    return &OpenSSLConn{ssl: ssl, fd: int(fd), raw: tcpConn}, nil
}

