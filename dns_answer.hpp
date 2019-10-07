typedef struct dns_answers{
    unsigned type :16;
    unsigned class_ :16;
    unsigned ttl :32;
    unsigned rdlength :16;
}dns_answer;