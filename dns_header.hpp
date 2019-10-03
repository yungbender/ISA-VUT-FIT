typedef struct dns_headers{
    int id :16; // ID of question
    int qr :1; // query(0) or response(1) bit 
    int opcode :4; // type of querry (0, normal query)
    int aa :1;
    int tc :1;
    int rd :1;
    int ra :1;
    int reserved :3;
    int rcode :4;
    int qdcount :16;
    int ancount :16;
    int nscount :16;
    int arcount :16;
}dns_header;