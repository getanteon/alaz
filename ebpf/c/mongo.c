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