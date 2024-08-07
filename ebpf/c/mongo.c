//go:build ignore
// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
// Mongo Request Query
// 4 bytes message len
// 4 bytes request id
// 4 bytes response to
// 4 bytes opcode (2004 for Query)
// 4 bytes query flags
// fullCollectionName : ?
// 4 bytes number to skip
// 4 bytes number to return
// 4 bytes Document Length
// Elements

// Extensible Message Format
// 4 bytes len
// 4 bytes request id
// 4 bytes response to
// 4 bytes opcode (2013 for extensible message format)
// 4 bytes message flags
// Section 
// 1 byte Kind (0 for body)
// BodyDocument
//      4 bytes document length
//      Elements 
// Section
// Kind : Document Sequence (1)
// SeqId: "documents"
// DocumentSequence
//      Document
//          4 bytes doc len

// For response:
// same with above

#define MONGO_OP_COMPRESSED 2012 // Wraps other opcodes using compression
#define MONGO_OP_MSG        2013 // Send a message using the standard format. Used for both client requests and database replies.

// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#standard-message-header
struct mongo_header {
    __s32 length; // total message size, including this
    __s32 request_id;  // identifier for this message
    __s32 response_to; // requestID from the original request (used in responses from the database)
    __s32 opcode;  // message type
};

struct mongo_header_wout_len {
    // __s32 length; // total message size, including this
    __s32 request_id;  // identifier for this message
    __s32 response_to; // requestID from the original request (used in responses from the database)
    __s32 opcode;  // message type
};

static __always_inline
int is_mongo_request(char *buf, __u64 buf_size) {
    struct mongo_header h = {};
    if (bpf_probe_read(&h, sizeof(h), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (h.response_to == 0 && (h.opcode == MONGO_OP_MSG || h.opcode == MONGO_OP_COMPRESSED)) {
        bpf_printk("this is a mongo_request\n");
        return 1;
    }
    return 0;
}

// mongo replies read in 2 parts
// [pid 286873] read(7, "\x2d\x00\x00\x00", 4) = 4 // these 4 bytes are length
// [pid 286873] read(7, "\xe1\x0b\x00\x00 \x09\x00\x00\x00 \xdd\x07\x00\x00  // request_id - response_to - opcode
// \x00\x00\x00\x00\x00\x18\x00\x00\x00\x10
//             \x6e\x00
//             \x01\x00\x00\x00\x01\x6f\x6b\x00"..., 41) = 41static __always_inline
                                // (ok)
static __always_inline
int is_mongo_reply(char *buf, __u64 buf_size) {
    struct mongo_header_wout_len h = {};
    if (bpf_probe_read(&h, sizeof(h), (void *)((char *)buf)) < 0) {
        bpf_printk("this is a mongo_reply_header_fail\n");
        return 0;
    }
    if (h.response_to == 0) {
        bpf_printk("this is a mongo_reply_response_to0, - %d\n",h.opcode);
        return 0;
    }
    if (h.opcode == MONGO_OP_MSG || h.opcode == MONGO_OP_COMPRESSED) {
        bpf_printk("this is a mongo_reply\n");
        return 1;
    }
    
    bpf_printk("this is a mongo_reply-fail - %d\n",h.opcode);
    return 0;
}

