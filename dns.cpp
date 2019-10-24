// Project for subject Network Applications and Network Administration
// DNS Resolver
// Author: Tomáš Sasák, xsasak01@stud.fit.vutbr.cz
// BUT FIT 2019

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include "dns_header.hpp"
#include "dns_question.hpp"
#include "dns_answer.hpp"
#include "record_types.hpp"
#include "soa_header.hpp"

void error(std::string error)
{
    std::cerr << error;
    exit(1);
}

///////////////////////////////////////////////

/**
 * Class representing command line arguments.
 */
class Arguments
{
    public:
        // Flag if recursion was requested by user
        bool recursionDesired;
        // Flag if user wants to use reverse query
        bool reverseQuery;
        // Flag if user wants AAAA record (ipv6)
        bool ipv6;
        // String of user dns server argument
        std::string dnsServer;
        // Port where to send the dns request
        std::string port;
        // Target for host translation
        std::string target;
        /**
         * Function parses arguments from command line and saves the into the instance of this class.
         * 
         * @param argc Number of arguments
         * @param argv Pointer to the array of arguments
         * @return Function returns initialized instance of Arguments
         */
        static Arguments* parse_arguments(int argc, char **argv);

    /**
     * Arguments constructor
     */
    Arguments()
    {
        // Initial settings
        this->recursionDesired = false;
        this->reverseQuery = false;
        this->ipv6 = false;
        this->dnsServer = "";
        this->port = "53"; // Default DNS port
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

    // Check for additional arguments
    if ((optind + 1) != argc)
    {
        error("Error, unusual parameters given!\n");
    }
    // Check if server is missing
    else if (!wasServer)
    {
        error("Missing -s argument!\n");
    }

    arguments->target = argv[optind];
    return arguments;
}

///////////////////////////////////////////////

/**
 * Class sends dns packet and recieves answer.
 */
class DnsSender
{
    public:
        /**
         * Method sends DNS packet (question) to the given server using socket,
         * and returns pointer to the recieved DNS packet (answer).
         * 
         * @param args Pointer to the object of class Arguments which has user arguments
         * @param dnsResponseSize Pointer containing how big is the DNS answer packet
         */
        char* send_query(Arguments *args, int *dnsResponseSize);
    
    private:
        /**
         * Method fetches the given DNS server and sets up the socket based by
         * the options given from getaddrinfo(). Socket handle is in variable dnsSocket.
         * 
         * @param dnsServer DNS server given from user, where program will ask
         * @param port Port number where to ask
         * @param args Arguments given by user
         * 
         */
        void set_dns_socket(std::string dnsServer, std::string port, Arguments *args);
        /**
         * Method creates DNS packet (query) which contains question and settings
         * for dns server. Function returns the size of the packet in pointer variable
         * dnsPacketSize.
         * 
         * @param args User arguments
         * @param dnsPacketSize Size of the packet
         */
        char* create_dns_packet(Arguments *args, int *dnsPacketSize);
        /**
         * Method splits the target string by delimeter into vector.
         * (explode in php)
         * @param target String which needs to be splitted
         * @param delimeter Delimeter by which the split will be
         * 
         * @return Method returns vector of splitted strings
         */
        std::vector<std::string> split_target(std::string target, char delimeter);
        // Socket handle
        int dnsSocket;
};

void DnsSender::set_dns_socket(std::string dnsServer, std::string port, Arguments *args)
{
    struct addrinfo hints;
    struct addrinfo *result, *backup;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if((getaddrinfo(dnsServer.c_str(), port.c_str(), &hints, &result)) != 0)
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
            if((connect(this->dnsSocket, result->ai_addr, result->ai_addrlen)) == -1)
            {
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

    freeaddrinfo(backup);
}

std::vector<std::string> DnsSender::split_target(std::string target, char delimeter)
{
    std::replace(target.begin(), target.end(), delimeter, ' ');

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
    // If its reversequery revert the IP address 
    if(args->reverseQuery)
    {
        char buffer[16];
        // Check if the given address is ipv4 or ipv6
        if(inet_pton(AF_INET, args->target.c_str(), &buffer))
            args->ipv6 = false;
        else if(inet_pton(AF_INET6, args->target.c_str(), &buffer))
            args->ipv6 = true;
        else 
            error("Invalid IP address given!\n");
        
        // If it is ipv4 split by dot and add in-addr arpa for reverse search
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
        // If it is ipv6, transfer the address into binary representation
        // and save each byte as HEX value to parse the address without
        // loosing nerves and life, also add ip6 arpa 
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
        // It is domain, split the target by dots
        tokens = this->split_target(args->target, '.');
    }
    
    // Allocate first part of dns packet, dns header
    dns_header *dnsHeader = (dns_header *)malloc(sizeof(dns_header));

    // Make a startup backup of this packet
    char *dnsPacket = (char *)dnsHeader;
    memset(dnsHeader, 0, sizeof(dns_header));

    dnsHeader->opcode = 0; // 0 (query)
    dnsHeader->id = htons(1337); // Random ID
    dnsHeader->rd = args->recursionDesired ? 1 : 0; // Recursion desirec
    dnsHeader->qdcount = htons(1); // Number of question, always one question

    // Offset of dns question size in bytes
    int dnsQuestionOffset = sizeof(dns_header);

    // For every part(label) of requested domain/IP create the labels in the Question section
    for(std::size_t index = 0; index < tokens.size(); index++)
    {
        // Number of labels
        int length = tokens[index].length();

        // Create new space in DNS packet for the single label + byte which signifies length of label in bytes 
        dnsHeader = (dns_header *)realloc(dnsHeader, (dnsQuestionOffset + tokens[index].length() + sizeof(char)));
        dnsPacket = (char *)dnsHeader;

        // Copy length of label in packet
        memcpy((dnsPacket + dnsQuestionOffset), &length, sizeof(char));
        dnsQuestionOffset += sizeof(char);

        // Copy label in packet
        memcpy((dnsPacket + dnsQuestionOffset), tokens[index].c_str(), length);
        dnsQuestionOffset += length;
    }

    // Allocate the 0x00 label at the end
    dnsHeader = (dns_header *)realloc(dnsHeader, (dnsQuestionOffset) + sizeof(char));
    dnsPacket = (char *)dnsHeader;

    int zero = 0;
    memcpy((dnsPacket + dnsQuestionOffset), &zero, sizeof(char));
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

char* DnsSender::send_query(Arguments *args, int *dnsResponseSize)
{
    // Setup the socket for sending
    this->set_dns_socket(args->dnsServer, args->port, args);

    // Create DNS query packet
    int dnsPacketSize = 0;
    char *dnsPacket = this->create_dns_packet(args, &dnsPacketSize);

    // Send the packet
    send(this->dnsSocket, dnsPacket, dnsPacketSize, 0);

    free(dnsPacket);

    // set timeout on recv 
    struct timeval tv;
    tv.tv_sec = DNS_RESPONSE_WAIT;
    tv.tv_usec = 0;

    setsockopt(this->dnsSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    
    char *buffer = (char *)malloc(MAX_DNS_SIZE);
    int recieved = 0;

    if((recieved = recv(this->dnsSocket, buffer, MAX_DNS_SIZE, 0)) < 0)
    {
        if(errno != EINTR)
            error(strerror(errno));
    }

    close(this->dnsSocket);
    *dnsResponseSize = recieved;
    // Return the useless bites
    return (char *)realloc(buffer, recieved + 1);
}

///////////////////////////////////////////////

/**
 * Class parses the DNS answer packet and prints output.
 */
class DnsParser
{
    public:
        /**
         * Method parses the DNS response packet and prints out the results.
         * 
         * @param dnsResponse Pointer to the DNS response packet
         * @param dnsResponseSize Size of the packet
         */
        void parse_dns_response(char *dnsResponse, int *dnsResponseSize);
        /**
         * Method parses the label part in the DNS section.
         * 
         * @param labelStart Pointer to the start of the labels
         * @param allowPointer Bool which signifies, if the pointer is allowed
         * (pointer is used in the DNS answers, to compress the size of the DNS
         * packet by including pointer for repeating label, to not repeat it again)
         * @param dnsStart Pointer to the beginning of the DNS answer packet.
         * 
         * @return Method returns pointer to the DNS answer packet where the labels stopped.
         */
        char* parse_labels(char *labelStart, bool allowPointer, char *dnsStart);
    private:
        /**
         * Method parses the ANSWER/AUTHORITY/ADDITIONAL section of DNS packet
         * answer.
         * 
         * @param dnsAnswer Pointer to the ANSWER/AUTHORITY/ADDITIONAL section of dns packet
         * @param answerCounts Number of items in the section
         * @param dnsResponse Pointer to the beginning of the DNS answer packet
         * 
         * @return Method returns pointer to the DNS answer packet after the end of section.
         */
        char* parse_answer(char *dnsAnswer, int answerCounts, char *dnsResponse);
};

char* DnsParser::parse_labels(char *labelStart, bool allowPointer, char *dnsStart)
{
    char *backup;
    backup = labelStart;
    bool wasBackedUp = false;

    while(*labelStart != 0)
    {
        uint16_t pointerCheck;
        memcpy(&pointerCheck, labelStart, sizeof(pointerCheck));
        pointerCheck = ntohs(pointerCheck);
        // Check if its pointer to name or name with labels
        // If the DNS label is compressed, the first two BITS will be 11
        // 1100 0000 == 0xC000
        if((pointerCheck >= (uint16_t)(0xC000)) && allowPointer)
        {
            // Get the pointer (offset) value by substracting the 1100 0000
            // Because the first 2 bits are taken by pointer definition 
            pointerCheck -= (uint16_t)(0xC000);
            // Skip the 2 octets of pointer and offset 
            labelStart = labelStart + sizeof(pointerCheck);
            // backup the original pointer to return it back correctly
            if(wasBackedUp == false)
            {
                backup = labelStart;
                wasBackedUp = true;
            }
            // Now get to the label given by pointer offset
            labelStart = dnsStart + (pointerCheck);

            // Continue parsing the pointer
            continue;
        }
        // It is not pointer, it is normal labeling
        // For the number in the first octet of label print the next characters from label
        int8_t labelValue = *((int8_t *)(labelStart));
        for(int8_t index = 0; index < labelValue; index++)
        {
            std::cout << labelStart[1 + index];
        }
        // get to the next label = Pointer to the token label + 1 byte (label number) + label chars itself
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
        // Labels are always at the start, parse them
        dnsAnswer = this->parse_labels(dnsAnswer, true, dnsResponse);
        std::cout << ", ";

        // Now parse the static part of Answer section
        dnsAnswerMiddle = (dns_answer *)dnsAnswer;

        dnsAnswerMiddle->type = ntohs(dnsAnswerMiddle->type);
        dnsAnswerMiddle->class_ = ntohs(dnsAnswerMiddle->class_);
        dnsAnswerMiddle->ttl = ntohl(dnsAnswerMiddle->ttl);
        dnsAnswerMiddle->rdlength = ntohs(dnsAnswerMiddle->rdlength);

        // Get pointer to the Record of the answer
        char *dnsRData = (char *)(dnsAnswerMiddle) + sizeof(dns_answer);

        switch(dnsAnswerMiddle->type)
        {
            case A:
                std::cout << "A, ";
                break;
            case NS:
                std::cout << "NS, ";
                break;
            case MD:
                std::cout << "MD, ";
                break;
            case MF:
                std::cout << "MF, ";
                break;
            case CNAME:
                std::cout << "CNAME, ";
                break;
            case SOA:
                std::cout << "SOA, ";
                break;
            case MB:
                std::cout << "MB, ";
                break;
            case MG:
                std::cout << "MG, ";
                break;
            case MR:
                std::cout << "MR, ";
                break;
            case NULL_R:
                std::cout << "NULL";
                break;
            case WKS:
                std::cout << "WKS, ";
                break;
            case PTR:
                std::cout << "PTR, ";
                break;
            case HINFO:
                std::cout << "HINFO, ";
                break;
            case MINFO:
                std::cout << "MINFO, ";
                break;
            case MX:
                std::cout << "MX, ";
                break;
            case TXT:
                std::cout << "TXT, ";
                break;
            case SRV:
                std::cout << "SRV, ";
                break;
            case AAAA:
                std::cout << "AAAA, ";
                break;
        }

        switch(dnsAnswerMiddle->class_)
        {
            case IN:
                std::cout << "IN, ";
                break;
            case CS:
                std::cout << "CS, ";
                break;
            case CH:
                std::cout << "CH, ";
                break;
            case HS:
                std::cout << "HS, ";
                break;
        }

        std::cout << "TTL: " << dnsAnswerMiddle->ttl << ", ";

        // Parse the record
        switch(dnsAnswerMiddle->type)
        {
            case A:
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, dnsRData, ip, INET_ADDRSTRLEN);
                std::cout << ip;
                break;
            case AAAA:
                char ipv6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, dnsRData, ipv6, INET6_ADDRSTRLEN);
                std::cout << ipv6;
                break;
            case CNAME:
                // CNAME has labels, parse them
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case PTR:
                // PTR has labels, parse them
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case NS:
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case SOA:
            {
                // parse MNAME 
                std::cout << "Primary name: ";
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                std::cout << ", ";
                // parse RNAME
                std::cout << "Responsible authority mailbox: ";
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                std::cout << ", ";
                // parse rest of SOA
                soa_header *soaTail = (soa_header *)dnsRData;
                soaTail->expire = ntohl(soaTail->expire);
                soaTail->refresh = ntohl(soaTail->refresh);
                soaTail->retry = ntohl(soaTail->retry);
                soaTail->serial = ntohl(soaTail->serial);
                soaTail->minimum = ntohl(soaTail->minimum);
                // print it
                std::cout << "Serial number: " << soaTail->serial << ", ";
                std::cout << "Refresh interval: " << soaTail->refresh << ", ";
                std::cout << "Retry interval: " << soaTail->retry << ", ";
                std::cout << "Expire limit: "  << soaTail->expire << ", ";
                std::cout << "Minimum TTL: " << soaTail->minimum;
            }   break;
            case MB:
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case MD:
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case MF:
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case MG:
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case MINFO:
                // parse RMAILBX
                std::cout << "Maling list: ";
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                std::cout << "Mailing errorbox: ";
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case MR:
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
                break;
            case MX:
            {
                // parse preference
                int16_t *preference = (int16_t *)dnsRData;
                std::cout << "Preference: " << ntohs(*preference);
                dnsRData = dnsRData + sizeof(int16_t);
                dnsRData = this->parse_labels(dnsRData, true, dnsResponse);
            }   break;
            default:
                std::cout << "unsupported parsing";
                break;
        }

        // Get to the next answer OR end of the section
        dnsAnswer = dnsAnswer + sizeof(dns_answer) + dnsAnswerMiddle->rdlength;
        std::cout << "\n";
    }

    return dnsAnswer;
}

void DnsParser::parse_dns_response(char *dnsResponse, int *dnsResponseSize)
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
        // Print the domain name in the question, in question there are no pointers
        dnsQuestionTail = (dns_question*)(this->parse_labels(dnsQuestion, false, dnsResponse));
        std::cout << ", ";

        // Get the correct byte order
        dnsQuestionTail->qclass = ntohs(dnsQuestionTail->qclass);
        dnsQuestionTail->qtype = ntohs(dnsQuestionTail->qtype);

        switch(dnsQuestionTail->qtype)
        {
            case A:
                std::cout << "A, ";
                break;
            case NS:
                std::cout << "NS, ";
                break;
            case CNAME:
                std::cout << "CNAME, ";
                break;
            case SOA:
                std::cout << "SOA, ";
                break;
            case WKS:
                std::cout << "WKS, ";
                break;
            case PTR:
                std::cout << "PTR, ";
                break;
            case MX:
                std::cout << "MX, ";
                break;
            case SRV:
                std::cout << "SRV, ";
                break;
            case AAAA:
                std::cout << "AAAA, ";
                break;
            case 255:
                std::cout << "ANY, ";
                break;
        }

        switch(dnsQuestionTail->qclass)
        {
            case IN:
                std::cout << "IN \n";
                break;
            case CS:
                std::cout << "CS \n";
                break;
            case CH:
                std::cout << "CH \n";
                break;
            case HS:
                std::cout << "HS \n";
                break;
        }

        // Get to the end of single dns question
        dnsQuestion = ((char *)dnsQuestionTail) + sizeof(dns_question);
    }

    std::cout << "Answer section(" << dnsHeaderResponse->ancount << ") \n";

    // Parsing of ANSWER, AUTHORITY, ADDITIONAL section is the same

    char *dnsAnswer = dnsQuestion;
    dnsAnswer = this->parse_answer(dnsAnswer, dnsHeaderResponse->ancount, dnsResponse);

    std::cout << "Authority section(" << dnsHeaderResponse->nscount << ") \n";
    dnsAnswer = this->parse_answer(dnsAnswer, dnsHeaderResponse->nscount, dnsResponse);

    std::cout << "Additional section(" << dnsHeaderResponse->arcount << ") \n";
    dnsAnswer = this->parse_answer(dnsAnswer, dnsHeaderResponse->arcount, dnsResponse);
}

///////////////////////////////////////////////

int main(int argc, char *argv[])
{
    Arguments *arguments = Arguments::parse_arguments(argc, argv);

    DnsSender *dnsSender = new DnsSender;
    int dnsResponseSize;
    char *dnsResponse = dnsSender->send_query(arguments, &dnsResponseSize);

    DnsParser *dnsParser = new DnsParser;
    dnsParser->parse_dns_response(dnsResponse, &dnsResponseSize);

    free(dnsResponse);
    delete arguments;
    delete dnsSender;
}
