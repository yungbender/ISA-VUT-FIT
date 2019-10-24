#ifndef SOA_H
#define SOA_H

#include <stdint.h>

typedef struct soa_headers{
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire; 
    uint32_t minimum;
}soa_header;

#endif