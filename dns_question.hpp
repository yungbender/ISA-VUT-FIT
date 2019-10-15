#ifndef DNSQ_H
#define DNSQ_H

typedef struct dns_questions{
    int qtype :16;
    int qclass :16;
    
}dns_question;

#endif