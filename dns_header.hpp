#pragma pack(push, 1)
typedef struct dns_headers{
    unsigned id :16; // ID of question
    unsigned rd :1;
    unsigned tc :1;
    unsigned aa :1;
    unsigned opcode :4; // type of querry (0, normal query)
    unsigned qr :1; // query(0) or response(1) bit 
    unsigned rcode :4;
    unsigned reserved :3;
    unsigned ra :1;
    unsigned qdcount :16;
    unsigned ancount :16;
    unsigned nscount :16;
    unsigned arcount :16;
}dns_header;
