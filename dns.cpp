// Project for subject Computer Communications and Networks
// TCP/UDP port scanner
// Author: Tomáš Sasák
// BUT FIT 2019

#include "dns.hpp"
#include "dns_header.hpp"
#include "dns_question.hpp"

#define A 1
#define AAAA 28
#define IN 1

#define BUFFER_SIZE 65527

void error(std::string error)
{
    std::cerr << error;
    exit(1);
}

/**
 * Class representing command line arguments.
 */
class Arguments
{
    public:
        bool recursionDesired;
        bool reverseQuery;
        bool ipv6;
        std::string dnsServer;
        std::string port;
        std::string target;
        static Arguments* parse_arguments(int argc, char **argv);

    Arguments()
    {
        this->recursionDesired = false;
        this->reverseQuery = false;
        this->ipv6 = false;
        this->dnsServer = "";
        this->port = "53";
        this->target = "";
    }
};

Arguments* Arguments::parse_arguments(int argc, char **argv)
{
    Arguments *arguments = new Arguments();

    bool wasServer = false;
    char option;
    while((option = getopt(argc, argv, "r::x::6::s:p:")) != -1)
    {
        switch(option)
        {
            case 'r':
                arguments->recursionDesired = true;
                break;
            case 'x':
                arguments->reverseQuery = true;
                break;
            case '6':
                arguments->ipv6 = true;
                break;
            case 's':
                arguments->dnsServer = optarg;
                wasServer = true;
                break;
            case 'p':
                arguments->port = optarg;
                break;
        }
    }

    if ((optind + 1) != argc)
    {
        error("Error, unusual parameters given!\n");
    }
    else if (!wasServer)
    {
        error("Missing -s argument!\n");
    }

    arguments->target = argv[optind];
    return arguments;
}

class DnsSender
{
    public:
        char* send_query(Arguments *args, int *dnsResponseSize, int *dnsQuestionOffset);
    
    private:
        void set_dns_socket(std::string dnsServer, std::string port);
        char* create_dns_packet(Arguments *args, int *dnsPacketSize);
        std::vector<std::string> split_target(const char *target);
        int dnsSocket;
    
};

void DnsSender::set_dns_socket(std::string dnsServer, std::string port)
{
    struct addrinfo hints;
    struct addrinfo *result, *backup;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    int retval;

    if((retval = getaddrinfo(dnsServer.c_str(), port.c_str(), &hints, &result)) != 0)
    {
        error("Cannot fetch given dns server!\n");
    }

    backup = result;

    while(result != NULL)
    {
        std::cout << result->ai_family << "\n";
        if(result->ai_family == AF_INET || result->ai_family == AF_INET6)
        {            
            if((this->dnsSocket = socket(result->ai_family, SOCK_DGRAM, 0)) == -1)
            {
                error("Cannot create socket!\n");
            }
            if((retval = connect(this->dnsSocket, result->ai_addr, result->ai_addrlen)) == -1)
            {
                error(strerror(errno));
                error("Cannot connect to the dns server!\n");
            }
            break;
        }
        result = result->ai_next;
    }

    if(result == NULL)
    {
        error("Cannot fetch given dns server!\n");
    }

    std::cout << "DNS server is allright!\n";

    freeaddrinfo(backup);

}

std::vector<std::string> DnsSender::split_target(const char *target)
{
    char *copy = (char *)malloc(strlen(target));
    memcpy(copy, target, strlen(target));

    std::vector<std::string> tokens;
    
    char *token = strtok(copy, ".");
    while(token != NULL)
    {
        tokens.push_back(std::string(token));
        token = strtok(NULL, ".");
    }

    free(copy);
    return tokens;
}

char* DnsSender::create_dns_packet(Arguments *args, int *dnsPacketSize)
{
    std::vector<std::string> tokens = this->split_target(args->target.c_str());

    // Allocate first part of dns packet, dns header
    dns_header *dnsHeader = (dns_header *)malloc(sizeof(dns_header));

    // Make a startup backup of this packet
    char *dnsPacket = (char *)dnsHeader;


    memset(dnsHeader, 0, sizeof(dns_header));
    dnsHeader->opcode = 0;
    dnsHeader->id = htons(1337);
    dnsHeader->rd = args->recursionDesired ? 1 : 0;
    dnsHeader->qdcount = htons(1);
    dnsHeader->opcode = args->reverseQuery ? 1 : 0;

    // Offset of dns question size in bytes
    int dnsQuestionOffset = sizeof(dns_header);

    // For every part of target query, allocate new place and insert it in dns question
    for(std::size_t index = 0; index < tokens.size(); index++)
    {
        int length = tokens[index].length();
        //int length_htons = htons(length);

        std::cout << (tokens[index].length()) << "\n";
        std::cout << tokens[index] << "\n";

        // Create new space in dns packet for the length of token and actual token
        dnsHeader = (dns_header *)realloc(dnsHeader, (dnsQuestionOffset + tokens[index].length() + sizeof(char)));
        dnsPacket = (char *)dnsHeader;


        // Copy length of token in packet
        memcpy((dnsPacket + dnsQuestionOffset), &length, sizeof(char));
        dnsQuestionOffset += sizeof(char);

        // Copy token in packet
        memcpy((dnsPacket + dnsQuestionOffset), tokens[index].c_str(), length);
        dnsQuestionOffset += length;
    }

    // Allocate the 0x00 label at the end
    dnsHeader = (dns_header *)realloc(dnsHeader, (dnsQuestionOffset) + sizeof(char));
    dnsPacket = (char *)dnsHeader;

    int zero = 0;
    memcpy((dnsPacket+dnsQuestionOffset), &zero, sizeof(char));
    dnsQuestionOffset += sizeof(char);

    // Allocate new place for the rest of dns question
    dnsHeader = (dns_header *)realloc(dnsHeader, (dnsQuestionOffset + sizeof(dns_question)));
    dnsPacket = (char *)dnsHeader;

    dns_question *dnsQuestion = (dns_question*)(dnsPacket + dnsQuestionOffset);
    dnsQuestion->qtype = args->ipv6 ? htons(AAAA) : htons(A);
    dnsQuestion->qclass = htons(IN);

    dnsQuestionOffset += sizeof(dns_question);

    *dnsPacketSize = dnsQuestionOffset;
    return dnsPacket;
}

char* DnsSender::send_query(Arguments *args, int *dnsResponseSize, int *dnsQuestionOffset)
{
    this->set_dns_socket(args->dnsServer, args->port);

    int dnsPacketSize = 0;
    char *dnsPacket = this->create_dns_packet(args, &dnsPacketSize);

    send(this->dnsSocket, dnsPacket, dnsPacketSize, 0);

    free(dnsPacket);

    // set timeout on recv 
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int retval = setsockopt(this->dnsSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    std::cout << "retval:" << retval << "\n";

    char *buffer = (char *)malloc(BUFFER_SIZE);
    int recieved = 0;

    if((recieved = recv(this->dnsSocket, buffer, BUFFER_SIZE, 0)) < 0)
    {
        if(errno != EINTR)
            error(strerror(errno));
    }

    std::cout << "dns packet size recieved:" << recieved << "\n";
    std::cout << "\n";

    close(this->dnsSocket);
    *dnsResponseSize = recieved;
    *dnsQuestionOffset = dnsPacketSize;
    // Return the useless bites
    return (char *)realloc(buffer, recieved + 1);
}

class DnsParser
{
    public:
        void parse_dns_response(char *dnsResponse, int *dnsResponseSize, int *dnsQuestionOffset);
};

void DnsParser::parse_dns_response(char *dnsResponse, int *dnsResponseSize, int *dnsQuestionOffset)
{
    // Preparse dns header from response
    dns_header *dnsHeaderResponse = (dns_header *)dnsResponse;

    // Translate to little endian things from server
    dnsHeaderResponse->id = ntohs(dnsHeaderResponse->id);
    dnsHeaderResponse->qdcount = ntohs(dnsHeaderResponse->qdcount);
    dnsHeaderResponse->ancount = ntohs(dnsHeaderResponse->ancount);
    dnsHeaderResponse->nscount = ntohs(dnsHeaderResponse->nscount);
    dnsHeaderResponse->arcount = ntohs(dnsHeaderResponse->arcount);
    
    std::cout << "Header section:" << "\n";
    if(dnsHeaderResponse->qr == 1)
        std::cout << "Type: Answer, ";
    else
        std::cout << "Type: Question, ";
    
    if(dnsHeaderResponse->opcode == 0)
        std::cout << "Opcode: QUERY, ";
    else if(dnsHeaderResponse->opcode == 1)
        std::cout << "Opcode: IQUERY, ";
    else
        std::cout << "Opcode: STATUS, ";

    if(dnsHeaderResponse->aa == 1)
        std::cout << "Authorative answer: Yes, ";
    else 
        std::cout << "Authorative answer: No, ";

    if(dnsHeaderResponse->tc == 0)
        std::cout << "Trucanted: No, ";
    else 
        std::cout << "Truncated: Yes, ";
    
    if(dnsHeaderResponse->rd == 1)
        std::cout << "Recursion desired: Yes, ";
    else 
        std::cout << "Recursion desired: No, ";
    
    if(dnsHeaderResponse->ra == 1)
        std::cout << "Recursion avaiable: Yes, ";
    else 
        std::cout << "Recursion avaiable: No, ";
    
    if(dnsHeaderResponse->rcode == 0)
        std::cout << "Reply code: 0 ";
    else 
        std::cout << "Reply code: " << dnsHeaderResponse->rcode;
    
    std::cout << "\n" << "Question section(" << dnsHeaderResponse->qdcount << ")\n";
    char *dnsQuestion = ((char *)dnsHeaderResponse) + sizeof(dns_header);
    dns_question *dnsQuestionTail = NULL;
    // Print the domain name in question
    for(int i = 0; i < dnsHeaderResponse->qdcount; i++)
    {
        // Until there is not 0x00 in packet (that means end of domain name)
        while(dnsQuestion[0] != 0)
        {
            // For the number in the first octet of label print the next characters from label
            for(int index = 0; index < int(dnsQuestion[0]); index++)
            {
                std::cout << dnsQuestion[1 + index];
            }
            // get to the next token = Pointer to the token label + 1 byte (label number) + label chars itself
            dnsQuestion = int(dnsQuestion[0]) + dnsQuestion + 1;

            // If its not last label, print dot
            if(dnsQuestion[0] != 0)
                std::cout << ".";
            else 
                std::cout << ", ";
        }

        // Now the rest of the question header
        dnsQuestionTail = (dns_question *)(dnsQuestion + 1);

        // Get the correct byte order
        dnsQuestionTail->qclass = ntohs(dnsQuestionTail->qclass);
        dnsQuestionTail->qtype = ntohs(dnsQuestionTail->qtype);

        switch(dnsQuestionTail->qtype)
        {
            case 1:
                std::cout << "A, ";
                break;
            case 2:
                std::cout << "NS, ";
                break;
            case 5:
                std::cout << "CNAME, ";
                break;
            case 6:
                std::cout << "SOA, ";
                break;
            case 11:
                std::cout << "WKS, ";
                break;
            case 12:
                std::cout << "PTR, ";
                break;
            case 15:
                std::cout << "MX, ";
                break;
            case 33:
                std::cout << "SRV, ";
                break;
            case 28:
                std::cout << "AAAA, ";
                break;
            case 255:
                std::cout << "ANY, ";
                break;
        }

        if(dnsQuestionTail->qclass == 1)
        {
            std::cout << "IN \n";
        }

        // Get to the end of singlle dns question
        dnsQuestion = (char *)dnsQuestionTail + sizeof(dns_question);
    }

    std::cout << "Answer section(" << dnsHeaderResponse->ancount << ") \n";

}

int main(int argc, char *argv[])
{
    Arguments *arguments = Arguments::parse_arguments(argc, argv);
    std::cout << "Ipv6 requested: " << arguments->ipv6 << "\n";
    std::cout << "Dns server Port requested: " << arguments->port << "\n";
    std::cout << "Recursion: " << arguments->recursionDesired << "\n"; 
    std::cout << "Reverse: " << arguments->reverseQuery << "\n"; 
    std::cout << "Dns server: " << arguments->dnsServer << "\n";
    std::cout << "Target: " <<arguments->target << "\n";

    DnsSender *dnsSender = new DnsSender;
    int dnsResponseSize, dnsQuestionOffset;
    char *dnsResponse = dnsSender->send_query(arguments, &dnsResponseSize, &dnsQuestionOffset);

    DnsParser *dnsParser = new DnsParser;
    dnsParser->parse_dns_response(dnsResponse, &dnsResponseSize, &dnsQuestionOffset);

    free(dnsResponse);
    delete arguments;
    delete dnsSender;
}