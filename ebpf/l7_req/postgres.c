// https://www.postgresql.org/docs/current/protocol.html
// PostgreSQL uses a message-based protocol for communication between frontends and backends (clients and servers).
// The protocol is supported over TCP/IP and also over Unix-domain sockets

// In order to serve multiple clients efficiently, the server launches a new “backend” process for each client.

// All communication is through a stream of messages.
// The first byte of a message identifies the message type, and the next four bytes specify the length of the rest of the message (this length count includes itself, but not the message-type byte)
// 1 byte of message type + 4 bytes of length + payload

// In the extended-query protocol, execution of SQL commands is divided into multiple steps.
// The state retained between steps is represented by two types of objects: prepared statements and portals

// A prepared statement represents the result of parsing and semantic analysis of a textual query string. A prepared statement is not in itself ready to execute, because it might lack specific values for parameters.
// A portal represents a ready-to-execute or already-partially-executed statement, with any missing parameter values filled in

// 1) parse step, which creates a prepared statement from a textual query string
// 2) bind step, which creates a portal (a prepared statement with parameter values filled in) from a prepared statement
// 3) execute step, which executes a portal's query
// In case of query returns rows, execute step maybe repeated multiple times

// As of PostgreSQL 7.4 the only supported formats are “text” and “binary”. Clients can specify a format code.
// binary representations for complex data types might change across server versions; the text format is usually the more portable choice

// state of the connection: start-up, query, function call, COPY, and termination

// The ReadyForQuery message is the same one that the backend will issue after each command cycle is completed.

// A simple query cycle is initiated by the frontend sending a Query message to the backend
// The message includes an SQL command (or commands) expressed as a text string
// The backend then sends one or more response messages depending on the contents of the query command string, and finally a ReadyForQuery response message
// CommandComplete
// RowDescription
// DataRow
// EmptyQueryResponse
// ErrorResponse

// SELECT - EXPLAIN - SHOW
// RowDescription, zero or more DataRow messages, and then CommandComplete

// a query string could contain several queries (separated by semicolons)

// Simple and Extended Query Modes

// In simple Query mode, the format of retrieved values is always text, except when the given command is a FETCH from a cursor declared with the BINARY option
// multi-statement Query message in an implicit transaction block

// In the extended protocol, the frontend first sends a Parse message, which contains a textual query string,
// optionally some information about data types of parameter placeholders, and the name of a destination prepared-statement object
// The response is either ParseComplete or ErrorResponse

// The query string contained in a Parse message cannot include more than one SQL statement; if it does, the backend will throw an error
// This restriction does not exist in the simple-query protocol, but it does exist in the extended protocol, because allowing prepared statements or portals to contain multiple commands would complicate the protocol unduly.

// If successfully created, a named prepared-statement object lasts till the end of the current session, unless explicitly destroyed

// unnamed statement

// Named prepared statements must be explicitly closed before they can be redefined by another Parse message
// Parse - Bind - Execute

// The simple Query message is approximately equivalent to the series Parse, Bind, portal Describe, Execute, Close, Sync, 
// using the unnamed prepared statement and portal objects and no parameters. 
// One difference is that it will accept multiple SQL statements in the query string, automatically performing the bind/describe/execute sequence for each one in succession.
// Another difference is that it will not return ParseComplete, BindComplete, CloseComplete, or NoData messages.

// Q(1 byte), length(4 bytes), query(length-4 bytes)
#define POSTGRES_MESSAGE_SIMPLE_QUERY 'Q' // 'Q' + 4 bytes of length + query

// C(1 byte), length(4 bytes), Byte1('S' to close a prepared statement; or 'P' to close a portal), name of the prepared statement or portal(length-5 bytes)
#define POSTGRES_MESSAGE_CLOSE 'C'

// X(1 byte), length(4 bytes)
#define POSTGRES_MESSAGE_TERMINATE 'X'

// C(1 byte), length(4 bytes), tag(length-4 bytes)
#define POSTGRES_MESSAGE_COMMAND_COMPLETION 'C'

// prepared statement
#define POSTGRES_MESSAGE_PARSE 'P' // 'P' + 4 bytes of length + query

#define METHOD_UNKNOWN      0
#define METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE   1
#define METHOD_SIMPLE_QUERY 2

#define COMMAND_COMPLETE 1
#define ERROR_RESPONSE 2
// #define ROW_DESCRIPTION 4
// #define DATA_ROW 5
// #define EMPTY_QUERY_RESPONSE 7
// #define NO_DATA 8
// #define PORTAL_SUSPENDED 9
// #define PARAMETER_STATUS 10
// #define BACKEND_KEY_DATA 11
// #define READY_FOR_QUERY 12

// should used on client side
// checks if the message is a postgresql Q, C, X message
static __always_inline
int parse_client_postgres_data(char *buf, int buf_size, __u8 *request_type) {
    if (buf_size < 1) {
        return 0;
    }
    char identifier;
    __u32 len;
    if (bpf_probe_read(&identifier, sizeof(identifier), (void *)((char *)buf)) < 0) {
        return 0;
    }

    if (bpf_probe_read(&len, sizeof(len), (void *)((char *)buf+1)) < 0) {
        return 0;
    }
    len = bpf_htonl(len);

    if (identifier == POSTGRES_MESSAGE_TERMINATE && len == 4) {
        *request_type = identifier;
        return 1;
    }

    
    // long queries can be split into multiple packets
    // therefore specified length can exceed the buf_size 
    // normally (len + 1 byte of identifier  == buf_size) should be true

    if (identifier == POSTGRES_MESSAGE_SIMPLE_QUERY) {
        *request_type = identifier;
        return 1;
    }

    return 0;
}

static __always_inline
__u32 parse_postgres_server_resp(char *buf, int buf_size) {
    char identifier;
    int len;
    if (bpf_probe_read(&identifier, sizeof(identifier), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (bpf_probe_read(&len, sizeof(len), (void *)((char *)buf+1)) < 0) {
        return 0;
    }
    len = bpf_htonl(len);

    if (len+1 > buf_size) {
        return 0;
    }

    // TODO: write a state machine to parse the response
    
    // '1' : ParseComplete
    // '2' : BindComplete
    // '3' : CloseComplete
    // 'T' : RowDescription
    // 'D' : DataRow
    // 'C' : CommandComplete
    // 'E' : ErrorResponse
    // 'I' : EmptyQueryResponse
    // 'N' : NoData
    // 'S' : PortalSuspended
    // 's' : ParameterStatus
    // 'K' : BackendKeyData
    // 'Z' : ReadyForQuery



    // if ((cmd == '1' || cmd == '2') && length == 4 && buf_size >= 10) {
    //     if (bpf_probe_read(&cmd, sizeof(cmd), (void *)((char *)buf+5)) < 0) {
    //         return 0;
    //     }
    //     if (bpf_probe_read(&length, sizeof(length), (void *)((char *)buf+5+1)) < 0) {
    //         return 0;
    //     }
    // }

    if (identifier == 'E') {
        return ERROR_RESPONSE;
    }

    // TODO: multiple pg messages can be in one packet, need to parse all of them and check if any of them is a command complete
    // assume C came if you see a T or D
    // when parsed C, it will have sql command in it (tag field, e.g. SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, etc.)
    if (identifier == 't' || identifier == 'T' || identifier == 'D' || identifier == 'C') {
        return COMMAND_COMPLETE;
    }

    return 0;
}
