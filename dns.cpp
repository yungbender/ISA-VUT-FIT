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
        void send_query(Arguments *args);
    
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
    dnsHeader->id = htons(1337);
    dnsHeader->rd = args->recursionDesired ? htons(1) : 0;
    dnsHeader->qdcount = htons(1);
    dnsHeader->opcode = args->reverseQuery ? htons(1) : 0;

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

void DnsSender::send_query(Arguments *args)
{
    this->set_dns_socket(args->dnsServer, args->port);

    int dnsPacketSize = 0;
    char *dnsPacket = this->create_dns_packet(args, &dnsPacketSize);

    send(this->dnsSocket, dnsPacket, dnsPacketSize, 0);

    free(dnsPacket);
    close(this->dnsSocket);


/*     char slovo[] = "kokot";
    send(this->dnsSocket, &slovo, sizeof(slovo), 0); */
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
    dnsSender->send_query(arguments);

    delete arguments;
    delete dnsSender;
}