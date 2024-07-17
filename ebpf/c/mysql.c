//go:build ignore
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase.html

// 01 00 00 00 01
//             ^^- command-byte
//          ^^---- sequence-id == 0

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
#define MYSQL_COM_QUERY 0x03 // Text Protocol

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase_ps.html
#define MYSQL_COM_STMT_PREPARE 0x16 // Creates a prepared statement for the passed query string.
// The server returns a COM_STMT_PREPARE Response which contains a statement-id which is ised to identify the prepared statement.

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html
#define MYSQL_COM_STMT_EXECUTE 0x17 // COM_STMT_EXECUTE asks the server to execute a prepared statement as identified by statement_id.


#define MYSQL_RESPONSE_OK    0x00
#define MYSQL_RESPONSE_EOF   0xfe
#define MYSQL_RESPONSE_ERROR 0xff

#define METHOD_UNKNOWN      0
#define METHOD_MYSQL_TEXT_QUERY 1
#define METHOD_MYSQL_PREPARE_STMT 2
#define METHOD_MYSQL_EXEC_STMT 3

#define MYSQL_STATUS_OK 1
#define MYSQL_STATUS_FAILED 2

static __always_inline
int is_mysql_query(char *buf, __u64 buf_size, __u8 *request_type) {
    if (buf_size < 5) {
        return 0;
    }
    __u8 b[5]; // first 5 bytes, first 3 represents length, 4th is packet number, 5th is command type
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }
    int len = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
    // command byte is inside the packet
    if (len+4 != buf_size || b[3] != 0) { // packet number must be 0
        return 0;
    }
    
    if (b[4] ==  MYSQL_COM_QUERY || b[4] == MYSQL_COM_STMT_EXECUTE) {
        *request_type = b[4];
        return 1;
    }

    // COM_STMT_CLOSE deallocates a prepared statement.
    // if (b[4] == MYSQL_COM_STMT_CLOSE) {
    //     *request_type = MYSQL_COM_STMT_CLOSE;
    //     return 1;
    // }

    if (b[4] == MYSQL_COM_STMT_PREPARE) {
        *request_type = MYSQL_COM_STMT_PREPARE;
        return 1;
    }
    return 0;
}

// __u32 *statement_id
static __always_inline
int is_mysql_response(char *buf, __u64 buf_size, __u8 request_type, __u32 *statement_id) {
    __u8 b[5]; // first 5 bytes, first 3 represents length, 4th is packet number, 5th is response code
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (b[3] <= 0) { // sequence must be > 0
        return 0;
    }
    int length = (int)b[0] | (int)b[1] << 8 | (int)b[2] << 16;
    
    if (length == 1 || b[4] == MYSQL_RESPONSE_EOF) {
        return MYSQL_STATUS_OK;
    }
    if (b[4] == MYSQL_RESPONSE_OK) {
        if (request_type == MYSQL_COM_STMT_PREPARE) {
            // 6-9th bytes returns statement id
            if (bpf_probe_read(statement_id, sizeof(*statement_id), (void *)((char *)buf+5)) < 0) {
                return 0;
            }
        }
        return MYSQL_STATUS_OK;
    }
    if (b[4] == MYSQL_RESPONSE_ERROR) {
        // *status = STATUS_FAILED;
        return MYSQL_STATUS_FAILED;
    }
    return 0;
}