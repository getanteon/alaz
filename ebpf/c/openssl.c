//go:build ignore
struct padding {};
typedef long (*padding_fn)();


//OpenSSL_1_0_2
struct ssl_st_v1_0_2 {
    __s32 version;
    __s32 type;
    struct padding* method; //  const SSL_METHOD *method;
    // ifndef OPENSSL_NO_BIO
    struct bio_st_v1* rbio;  // used by SSL_read
    struct bio_st_v1* wbio;  // used by SSL_write
};

struct bio_st_v1_0_2 {
    struct padding* method; // BIO_METHOD *method;
    padding_fn callback; // long (*callback) (struct bio_st *, int, const char *, int, long, long);
    char* cb_arg; /* first argument for the callback */
    int init;
    int shutdown;
    int flags; /* extra storage */
    int retry_reason;
    int num; // fd
};


//OpenSSL_1_1_1
struct ssl_st_v1_1_1 {
    __s32 version;
    struct padding* method; //  const SSL_METHOD *method;
    struct bio_st_v1_1_1* rbio;  // used by SSL_read
    struct bio_st_v1_1_1* wbio;  // used by SSL_write
};

struct bio_st_v1_1_1 {
    struct padding* method; // const BIO_METHOD *method;
    padding_fn callback; // long (*callback) (struct bio_st *, int, const char *, int, long, long);
    padding_fn callback_ex;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};

//openssl-3.0.0
struct ssl_st_v3_0_0 {
    __s32 version;
    struct padding* method; // const SSL_METHOD *method;
    /* used by SSL_read */
    struct bio_st_v3_0_0* rbio;
     /* used by SSL_write */
    struct bio_st_v3_0_0* wbio;

};

struct bio_st_v3_0 {
    struct padding* libctx;  // OSSL_LIB_CTX *libctx;
    struct padding* method;  // const BIO_METHOD *method;
    padding_fn callback;     // BIO_callback_fn callback;
    padding_fn callback_ex;  // BIO_callback_fn_ex callback_ex;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
    // void *ptr;
    // struct bio_st *next_bio;    /* used by filter BIOs */
    // struct bio_st *prev_bio;    /* used by filter BIOs */
    // CRYPTO_REF_COUNT references;
    // uint64_t num_read;
    // uint64_t num_write;
    // CRYPTO_EX_DATA ex_data;
    // CRYPTO_RWLOCK *lock;
};

// struct ssl_st {
//     /*
//      * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
//      * DTLS1_VERSION)
//      */
//     int version;
//     /* SSLv3 */
//     const SSL_METHOD *method;
//     /*
//      * There are 2 BIO's even though they are normally both the same.  This
//      * is so data can be read and written to different handlers
//      */
//     /* used by SSL_read */
//     BIO *rbio;
//     /* used by SSL_write */
//     BIO *wbio;
//     /* used during session-id reuse to concatenate messages */
//     BIO *bbio;
//     /*
//      * This holds a variable that indicates what we were doing when a 0 or -1
//      * is returned.  This is needed for non-blocking IO so we know what
//      * request needs re-doing when in SSL_accept or SSL_connect
//      */
//     int rwstate;
//     int (*handshake_func) (SSL *);
//     /*
//      * Imagine that here's a boolean member "init" that is switched as soon
//      * as SSL_set_{accept/connect}_state is called for the first time, so
//      * that "state" and "handshake_func" are properly initialized.  But as
//      * handshake_func is == 0 until then, we use this test instead of an
//      * "init" member.
//      */
//     /* are we the server side? */
//     int server;
//     /*
//      * Generate a new session or reuse an old one.
//      * NB: For servers, the 'new' session may actually be a previously
//      * cached session or even the previous session unless
//      * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
//      */
//     int new_session;
//     /* don't send shutdown packets */
//     int quiet_shutdown;
//     /* we have shut things down, 0x01 sent, 0x02 for received */
//     int shutdown;

//     ...
//     ...

// }