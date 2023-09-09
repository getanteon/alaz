struct unused {};
typedef long (*unused_fn)();

struct ssl_st_v1_1 {
    __s32 version;
    struct unused* method;
    struct bio_st_v1_1* rbio;  // used by SSL_read
    struct bio_st_v1_1* wbio;  // used by SSL_write
};

struct bio_st_v1_1 {
    struct unused* method;
    unused_fn callback;
    unused_fn callback_ex; // new field
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};
