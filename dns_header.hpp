#ifndef DNSH_H
#define DNSH_H

#pragma pack(push, 1)  // Stop padding

typedef struct dns_headers{
    unsigned id :16; // ID of question
    
    #if BYTE_ORDER == LITTLE_ENDIAN
    unsigned rd :1;
    unsigned tc :1;
    unsigned aa :1;
    unsigned opcode :4; // type of querry (0, normal query)
    unsigned qr :1; // query(0) or response(1) bit 
    unsigned rcode :4;
    unsigned reserved :3;
    unsigned ra :1;
    #else // BIG_ENDIAN 
    unsigned qr :1;
    unsigned opcode :4;
    unsigned aa :1;
    unsigned tc :1;
    unsigned rd :1;
    unsigned ra :1;
    unsigned reserved :3;
    unsigned rcode :4;    
    #endif

    unsigned qdcount :16;
    unsigned ancount :16;
    unsigned nscount :16;
    unsigned arcount :16;
}dns_header;

#endif
