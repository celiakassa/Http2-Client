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
#include <poll.h>
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

#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * Callback function for TLS NPN. Since this program only supports
 * HTTP/2 protocol, if server does not offer HTTP/2 the nghttp2
 * library supports, we terminate program.
 */
static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  int rv;
  (void)ssl;
  (void)arg;

  /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
     nghttp2 library supports. */
  rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
  if (rv <= 0) {
    fprintf(stderr, "Server did not advertise HTTP/2 protocol");
  }
  return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */


/*
 * Setup SSL/TLS context.
 */
static void init_ssl_ctx(SSL_CTX *ssl_ctx) {
  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  /* Set NPN callback */
#ifndef OPENSSL_NO_NEXTPROTONEG
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */
}

SSL_CTX* InitCTX(void) { 
    int ret;  
    //SSL_METHOD *method;
    SSL_CTX *ctx;
    /*SSL_library_init();
    OpenSSL_add_all_algorithms(); */ /* Load cryptos, et.al. */
    ret = OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
           OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, (OPENSSL_INIT_SETTINGS *)NULL);
    if(!ret){
        ERR_print_errors_fp(stderr);
        return (SSL_CTX*) NULL;
    }
    
    /* SSL_load_error_strings();   Bring in and register error messages */
   // method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(TLS_client_method());   /* Create new context */
    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        return (SSL_CTX*) NULL;
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

/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
  struct Connection *connection;
  int rv;
  (void)session;
  (void)flags;

  connection = (struct Connection *)user_data;
  connection->want_io = IO_NONE;
  ERR_clear_error();
  rv = SSL_write(connection->ssl, data, (int)length);
  if (rv <= 0) {
    int err = SSL_get_error(connection->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      connection->want_io =
          (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return rv;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                             size_t length, int flags, void *user_data) {
  struct Connection *connection;
  int rv;
  (void)session;
  (void)flags;

  connection = (struct Connection *)user_data;
  connection->want_io = IO_NONE;
  ERR_clear_error();
  rv = SSL_read(connection->ssl, buf, (int)length);
  if (rv < 0) {
    int err = SSL_get_error(connection->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      connection->want_io =
          (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else if (rv == 0) {
    rv = NGHTTP2_ERR_EOF;
  }
  return rv;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  size_t i;
  (void)user_data;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
      const nghttp2_nv *nva = frame->headers.nva;
      printf("[INFO] C ----------------------------> S (HEADERS)\n");
      for (i = 0; i < frame->headers.nvlen; ++i) {
        fwrite(nva[i].name, 1, nva[i].namelen, stdout);
        printf(": ");
        fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
        printf("\n");
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    printf("[INFO] C ----------------------------> S (RST_STREAM)\n");
    break;
  case NGHTTP2_GOAWAY:
    printf("[INFO] C ----------------------------> S (GOAWAY)\n");
    break;
  }
  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  size_t i;
  (void)user_data;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      const nghttp2_nv *nva = frame->headers.nva;
      struct Request *req;
      req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      if (req) {
        printf("[INFO] C <---------------------------- S (HEADERS)\n");
        for (i = 0; i < frame->headers.nvlen; ++i) {
          fwrite(nva[i].name, 1, nva[i].namelen, stdout);
          printf(": ");
          fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
          printf("\n");
        }
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    printf("[INFO] C <---------------------------- S (RST_STREAM)\n");
    break;
  case NGHTTP2_GOAWAY:
    printf("[INFO] C <---------------------------- S (GOAWAY)\n");
    break;
  }
  return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  struct Request *req;
  (void)error_code;
  (void)user_data;

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (req) {
    int rv;
    rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

    if (rv != 0) {
      diec("nghttp2_session_terminate_session", rv);
    }
  }
  return 0;
}

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
  struct Request *req;
  (void)flags;
  (void)user_data;

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (req) {
    printf("[INFO] C <---------------------------- S (DATA chunk)\n"
           "%lu bytes\n",
           (unsigned long int)len);
    fwrite(data, 1, len, stdout);
    printf("\n");
  }
  return 0;
}

/*
 * Setup callback functions. nghttp2 API offers many callback
 * functions, but most of them are optional. The send_callback is
 * always required. Since we use nghttp2_session_recv(), the
 * recv_callback is also required.
 */
static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks) {
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

  nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,
                                                       on_frame_send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);
}

/*
 * Update |pollfd| based on the state of |connection|.
 */
static void ctl_poll(struct pollfd *pollfd, struct Connection *connection) {
  pollfd->events = 0;
  if (nghttp2_session_want_read(connection->session) ||
      connection->want_io == WANT_READ) {
    pollfd->events |= POLLIN;
  }
  if (nghttp2_session_want_write(connection->session) ||
      connection->want_io == WANT_WRITE) {
    pollfd->events |= POLLOUT;
  }
}

/*
 * Performs the network I/O.
 */
static void exec_io(struct Connection *connection) {
  int rv;
  rv = nghttp2_session_recv(connection->session);
  if (rv != 0) {
    diec("nghttp2_session_recv", rv);
  }
  rv = nghttp2_session_send(connection->session);
  if (rv != 0) {
    diec("nghttp2_session_send", rv);
  }
}


int main(int count, char *argv[]) {   
    SSL_CTX *ctx;
    int fd;
    SSL *ssl;
    char buf[1024];
    struct Request req;
    struct Connection connection;
    int rv, ret;
    int bytes;
    char *hostname, *portnum;
    nghttp2_session_callbacks *callbacks;
    nfds_t npollfds = 1;
    struct pollfd pollfds[1];

    if ( count != 4 ){
        printf("usage: %s <hostname> <portnum> <resource>\n", argv[0]);
        exit(0);
    }
    hostname = argv[1];
    portnum = argv[2];
    
    //init request
    req.host = (char*) malloc(strlen(hostname)*sizeof(char));
    req.path = (char*) malloc(strlen(argv[3])*sizeof(char));
    req.hostport = (char*) malloc((strlen(hostname)+strlen(portnum)+1)*sizeof(char));
    
    strncpy(req.host, hostname, strlen(hostname));
    strncpy(req.path, argv[3], strlen(argv[3]));
    req.hostport = strcat(req.host, ":");
    req.hostport = strcat(req.hostport, portnum);
    req.port = atoi(portnum);
    
    /**TCP connection step**/
    
    fd = OpenConnection(hostname, atoi(portnum));
    
    if(fd < 0){
       fprintf(stderr, "Unable to establish TCP connection\n");
       exit(1);
    }
    /**End TCP connection step**/
    
    /** OpenSSL handshake **/
    ctx = InitCTX();
    if(ctx == NULL){
        fprintf(stderr, "Unable to initialize OpenSSL context\n");
        exit(1);
    }
  
    init_ssl_ctx(ctx);
    
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    if(ssl == NULL){
        ERR_print_errors_fp(stderr); 
        exit(1);
    }
    
    ret = SSL_set_fd(ssl, fd);    /* attach the socket descriptor */
    if(!ret){
        ERR_print_errors_fp(stderr); 
        exit(1);
    }
    ret = SSL_connect(ssl);
    
    if (!ret){   /* perform the connection */
        ERR_print_errors_fp(stderr);
    }
    /** end handshake **/
    
    //else
    //{   char *msg = "Hello???";
    //ShowCerts(ssl);        /* get any certs */
    connection.ssl = ssl;
    connection.want_io = IO_NONE; 
    //}
    /* Here make file descriptor non-block */
    make_non_block(fd);
    set_tcp_nodelay(fd);

    ret = nghttp2_session_callbacks_new(&callbacks);
    
    if(ret != 0){
       fprintf(stderr, "Unable to create session callback");
       exit(1);
    }
    
    setup_nghttp2_callbacks(callbacks);
    
    ret = nghttp2_session_client_new(&connection.session, callbacks, &connection);
    
    nghttp2_session_callbacks_del(callbacks);
    
    if(ret != 0){
       fprintf(stderr, "Failed to initialize session callback\n");
       exit(1);
    }
    
    ret = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, NULL, 0);
    
    if(ret != 0){
       fprintf(stderr, "Failed to submit NGHTTP2 settings\n");
       exit(1);
    }
    
    
    
    /* Submit the HTTP request to the outbound queue. */
    submit_request(&connection, &req);
    
    pollfds[0].fd = fd;
    ctl_poll(pollfds, &connection);
    
      /* Event loop */
    while (nghttp2_session_want_read(connection.session) ||
         nghttp2_session_want_write(connection.session)) {
       fprintf(stderr, "in loop\n");
       int nfds = poll(pollfds, npollfds, -1);
       if (nfds == -1) {
          fprintf(stderr, "poll: %s", strerror(errno));
       }
       if (pollfds[0].revents & (POLLIN | POLLOUT)) {
         exec_io(&connection);
       }
       if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
          fprintf(stderr, "Connection error");
       }
       ctl_poll(pollfds, &connection);
    }
    
    printf("before cleaning\n\n");
    goto clean;

   
clean:    
    nghttp2_session_del(connection.session);
    SSL_shutdown(ssl);
    SSL_free(ssl);        /* release connection state */
    SSL_CTX_free(ctx);        /* release context */
    close(fd);         /* close socket */
    return 0;
}

