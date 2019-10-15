// Project for subject Computer Communications and Networks
// TCP/UDP port scanner
// Author: Tomáš Sasák
// BUT FIT 2019

#include "dns.hpp"
#include "dns_header.hpp"
#include "dns_question.hpp"
#include "dns_answer.hpp"

#define A 1
#define AAAA 28
#define IN 1
#define PTR 12

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
        int addressType;
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
        void set_dns_socket(std::string dnsServer, std::string port, Arguments *args);
        char* create_dns_packet(Arguments *args, int *dnsPacketSize);
        std::vector<std::string> split_target(std::string target, char delimeter);
        int dnsSocket;
    
};

void DnsSender::set_dns_socket(std::string dnsServer, std::string port, Arguments *args)
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

std::vector<std::string> DnsSender::split_target(std::string target, char delimeter)
{
    std::replace(target.begin(), target.end(), '.', ' ');

    std::stringstream stringStream(target);
    std::vector<std::string> tokens;
    std::string backup;
    while(stringStream >> backup)
        tokens.push_back(backup);
    return tokens;
}

char* DnsSender::create_dns_packet(Arguments *args, int *dnsPacketSize)
{
    std::vector<std::string> tokens;
    // If its reversequery revert the IP address and add in addr arpa address
    if(args->reverseQuery)
    {
        // If it is ipv4 split by dot
        if(!args->ipv6)
        {
            tokens = this->split_target(args->target, '.');
            std::vector<std::string> tokensReverse;
            for(int i = (tokens.size() - 1); i >= 0; i--)
            {
                tokensReverse.push_back(tokens[i]);
            }

            tokensReverse.push_back("in-addr");
            tokensReverse.push_back("arpa");

            tokens = tokensReverse;
        }
        else
        {
            char ipv6[16];
            memset(&ipv6, 0, 16);

            inet_pton(AF_INET6, args->target.c_str(), &ipv6);

            std::ostringstream stream;
            stream << std::hex << std::setfill('0');
            for(int index : ipv6)
            {
                stream << std::setw(2) << index;
            }

            std::string result = stream.str();
            for(unsigned index = result.size() - 1; index < result.size(); index--)
            {
                tokens.push_back(std::string(1, result[index]));
            }
            tokens.push_back("ip6");
            tokens.push_back("arpa");
        }
        
    }
    else
    {
        // Split the target by dots
        tokens = this->split_target(args->target, '.');
    }
    

    for(long unsigned i = 0; i < tokens.size(); i++)
        std::cout << tokens[i] << "\n";

    // Allocate first part of dns packet, dns header
    dns_header *dnsHeader = (dns_header *)malloc(sizeof(dns_header));

    // Make a startup backup of this packet
    char *dnsPacket = (char *)dnsHeader;


    memset(dnsHeader, 0, sizeof(dns_header));
    dnsHeader->opcode = 0;
    dnsHeader->id = htons(1337);
    dnsHeader->rd = args->recursionDesired ? 1 : 0;
    dnsHeader->qdcount = htons(1);
    dnsHeader->opcode = 0;

    // Offset of dns question size in bytes
    int dnsQuestionOffset = sizeof(dns_header);

    // For every part of target query, allocate new place and insert it in dns question
    for(std::size_t index = 0; index < tokens.size(); index++)
    {
        int length = tokens[index].length();

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
    if(!args->reverseQuery)
        dnsQuestion->qtype = args->ipv6 ? htons(AAAA) : htons(A);
    else
        dnsQuestion->qtype = htons(PTR);
    
    dnsQuestion->qclass = htons(IN);

    dnsQuestionOffset += sizeof(dns_question);

    *dnsPacketSize = dnsQuestionOffset;
    return dnsPacket;
}

char* DnsSender::send_query(Arguments *args, int *dnsResponseSize, int *dnsQuestionOffset)
{
    this->set_dns_socket(args->dnsServer, args->port, args);

    int dnsPacketSize = 0;
    char *dnsPacket = this->create_dns_packet(args, &dnsPacketSize);

    send(this->dnsSocket, dnsPacket, dnsPacketSize, 0);

    free(dnsPacket);

    // set timeout on recv 
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(this->dnsSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    
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
    private:
        char* parse_answer(char *dnsAnswer, int answerCounts, char *dnsResponse);
};

char* parse_labels(char *labelStart, bool allowPointer, char *dnsStart)
{
    int pointer = 0;
    char *backup;
    backup = labelStart;
    bool wasBackedUp = false;

    while(*labelStart != 0)
    {
        uint16_t pointerCheck;
        memcpy(&pointerCheck, labelStart, sizeof(pointerCheck));
        pointerCheck = ntohs(pointerCheck);
        // Check if its pointer to name or name with labels
        if((pointerCheck >= (uint16_t)(0xC000)) && allowPointer)
        {
            // Get the pointer (offset) value by substracting the 11XX XXXX
            pointerCheck -= (uint16_t)(0xC000);
            // Skip the 2 octets of pointer and offest
            labelStart = labelStart + sizeof(pointerCheck);
            // backup the original pointer to return it back correctly
            if(wasBackedUp == false)
            {
                backup = labelStart;
                wasBackedUp = true;
            }
            // Now get to the offset of dns packet and also b
            labelStart = dnsStart + (pointerCheck);

            // Continue parsing the pointer
            pointer++;
            continue;
        }
        // For the number in the first octet of label print the next characters from label
        int8_t labelValue = *((int8_t *)(labelStart));
        for(int8_t index = 0; index < labelValue; index++)
        {
            std::cout << labelStart[1 + index];
        }
        // get to the next token = Pointer to the token label + 1 byte (label number) + label chars itself
        labelStart = labelValue + labelStart + 1;
        // If its not last label, print dot
        if(*labelStart != 0)
            std::cout << ".";
    }
    // If the pointer was backedup, need to return the backed up one
    if(wasBackedUp)
        return backup;
    // If the pointer was not backed up, return the the label + skip the 0x00
    else
        return labelStart + 1;
        
    
}

char* DnsParser::parse_answer(char *dnsAnswer, int answerCounts, char *dnsResponse)
{
    dns_answer *dnsAnswerMiddle;
    
    for(int i = 0; i < answerCounts; i++)
    {
        dnsAnswer = parse_labels(dnsAnswer, true, dnsResponse);
        std::cout << ", ";

        dnsAnswerMiddle = (dns_answer *)dnsAnswer;

        
        dnsAnswerMiddle->type = ntohs(dnsAnswerMiddle->type);
        dnsAnswerMiddle->class_ = ntohs(dnsAnswerMiddle->class_);
        dnsAnswerMiddle->ttl = ntohl(dnsAnswerMiddle->ttl);
        dnsAnswerMiddle->rdlength = ntohs(dnsAnswerMiddle->rdlength);

        char *dnsRData = (char *)(dnsAnswerMiddle) + sizeof(dns_answer);

        switch(dnsAnswerMiddle->type)
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
        }

        if(dnsAnswerMiddle->class_ == 1)
            std::cout << "IN, ";

        std::cout << "TTL: " << dnsAnswerMiddle->ttl << ", ";

        switch(dnsAnswerMiddle->type)
        {
            case 1:
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, dnsRData, ip, INET_ADDRSTRLEN);
                std::cout << ip;
                break;
            case 28:
                char ipv6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, dnsRData, ipv6, INET6_ADDRSTRLEN);
                std::cout << ipv6;
                break;
            case 5:
                dnsRData = parse_labels(dnsRData, true, dnsResponse);
                break;
            case PTR:
                dnsRData = parse_labels(dnsRData, true, dnsResponse);
                break;
        }

        // Get to the next answer, sizeof
        dnsAnswer = dnsAnswer + sizeof(dns_answer) + dnsAnswerMiddle->rdlength;
        std::cout << "\n";
    }

    return dnsAnswer;
}

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
        dnsQuestionTail = (dns_question*)(parse_labels(dnsQuestion, false, dnsResponse));
        std::cout << ", ";

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

        // Get to the end of single dns question
        dnsQuestion = ((char *)dnsQuestionTail) + sizeof(dns_question);
    }

    std::cout << "Answer section(" << dnsHeaderResponse->ancount << ") \n";

    char *dnsAnswer = dnsQuestion;
    dnsAnswer = this->parse_answer(dnsAnswer, dnsHeaderResponse->ancount, dnsResponse);

    std::cout << "Authority section(" << dnsHeaderResponse->nscount << ") \n";
    dnsAnswer = this->parse_answer(dnsAnswer, dnsHeaderResponse->nscount, dnsResponse);

    std::cout << "Additional section(" << dnsHeaderResponse->arcount << ") \n";
    dnsAnswer = this->parse_answer(dnsAnswer, dnsHeaderResponse->arcount, dnsResponse);
}

int main(int argc, char *argv[])
{
    Arguments *arguments = Arguments::parse_arguments(argc, argv);

    DnsSender *dnsSender = new DnsSender;
    int dnsResponseSize, dnsQuestionOffset;
    char *dnsResponse = dnsSender->send_query(arguments, &dnsResponseSize, &dnsQuestionOffset);

    DnsParser *dnsParser = new DnsParser;
    dnsParser->parse_dns_response(dnsResponse, &dnsResponseSize, &dnsQuestionOffset);

    free(dnsResponse);
    delete arguments;
    delete dnsSender;
}