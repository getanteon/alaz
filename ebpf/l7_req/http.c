
// int is_http_request(const char *buf) {
//     char b[16];
//     if (bpf_probe_read_str(&b, sizeof(b), (void *)buf) < 16) {
//         return 0;
//     }
//     if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T') {
//         return 1;
//     }
//     if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T') {
//         return 1;
//     }
//     if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D') {
//         return 1;
//     }
//     if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T') {
//         return 1;
//     }
//     if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' && b[5] == 'E') {
//         return 1;
//     }
//     if (b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && b[4] == 'E' && b[5] == 'C' && b[6] == 'T') {
//         return 1;
//     }
//     if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' && b[5] == 'N' && b[6] == 'S') {
//         return 1;
//     }
//     if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H') {
//         return 1;
//     }
//     return 0;
// }

// __u32 parse_http_status(char *buf) {
//     char b[16];
//     if (bpf_probe_read_str(&b, sizeof(b), (void *)buf) < 16) {
//         return 0;
//     }
//     if (b[0] != 'H' || b[1] != 'T' || b[2] != 'T' || b[3] != 'P' || b[4] != '/') {
//         return 0;
//     }
//     if (b[5] < '0' || b[5] > '9') {
//         return 0;
//     }
//     if (b[6] != '.') {
//         return 0;
//     }
//     if (b[7] < '0' || b[7] > '9') {
//         return 0;
//     }
//     if (b[8] != ' ') {
//         return 0;
//     }
//     if (b[9] < '0' || b[9] > '9' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9') {
//         return 0;
//     }
//     return (b[9]-'0')*100 + (b[10]-'0')*10 + (b[11]-'0');
// }
