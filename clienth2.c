#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <netinet/tcp.h>
#define FAIL    -1

enum { IO_NONE, WANT_READ, WANT_WRITE };

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_CS(NAME, VALUE)                                                \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),        \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

static void dief(const char *func, const char *msg) {
  fprintf(stderr, "FATAL: %s: %s\n", func, msg);
  exit(EXIT_FAILURE);
}
static void diec(const char *func, int error_code) {
  fprintf(stderr, "FATAL: %s: error_code=%d, msg=%s\n", func, error_code,
          nghttp2_strerror(error_code));
  exit(EXIT_FAILURE);
}

struct Connection {
  SSL *ssl;
  nghttp2_session *session;
  /* WANT_READ if SSL/TLS connection needs more input; or WANT_WRITE
     if it needs more output; or IO_NONE. This is necessary because
     SSL/TLS re-negotiation is possible at any time. nghttp2 API
     offers similar functions like nghttp2_session_want_read() and
     nghttp2_session_want_write() but they do not take into account
     SSL/TSL connection. */
  int want_io;
};

struct Request {
  char *host;
  /* In this program, path contains query component as well. */
  char *path;
  /* This is the concatenation of host and port with ":" in
     between. */
  char *hostport;
  /* Stream ID for this request. */
  int32_t stream_id;
  uint16_t port;
};

static void submit_request(struct Connection *connection, struct Request *req) {
  int32_t stream_id;
  /* Make sure that the last item is NULL */
  const nghttp2_nv nva[] = {MAKE_NV(":method", "GET"),
                            MAKE_NV_CS(":path", req->path),
                            MAKE_NV(":scheme", "https"),
                            MAKE_NV_CS(":authority", req->hostport),
                            MAKE_NV("accept", "*/*"),
                            MAKE_NV("user-agent", "nghttp2/" NGHTTP2_VERSION)};

  stream_id = nghttp2_submit_request(connection->session, NULL, nva,
                                     sizeof(nva) / sizeof(nva[0]), NULL, req);

  if (stream_id < 0) {
    
    diec("nghttp2_submit_request", stream_id);
  }

  req->stream_id = stream_id;
  printf("[INFO] Stream ID = %d\n", stream_id);
}
static void make_non_block(int fd) {
  int flags, rv;
  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
    ;
  if (flags == -1) {
      dief("fcntl", strerror(errno));
  }
  while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;
  if (rv == -1) {
     dief("fcntl", strerror(errno));
  }
}

static void set_tcp_nodelay(int fd) {
  int val = 1;
  int rv;
  rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
  if (rv == -1) {
    dief("setsockopt", strerror(errno));
  }
}

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{   
//SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
   // method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(SSLv23_client_method());   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int fd;
    SSL *ssl;
    char buf[1024];
     struct Request req;
  	struct Connection connection;
  	int rv;
    int bytes;
    char *hostname, *portnum;

    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];

    ctx = InitCTX();
    fd = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, fd);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   char *msg = "Hello???";

        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
       connection.ssl = ssl;
 	 connection.want_io = IO_NONE; 
    }
    /* Here make file descriptor non-block */
 	 make_non_block(fd);
  	set_tcp_nodelay(fd);

  	printf("[INFO] SSL/TLS handshake completed\n");
	/* Submit the HTTP request to the outbound queue. */
    submit_request(&connection, &req);

     SSL_free(ssl);        /* release connection state */
    close(fd);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}

