// Project for subject Computer Communications and Networks
// TCP/UDP port scanner
// Author: Tomáš Sasák
// BUT FIT 2019

#include "dns.hpp"

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
        int port;
        std::string target;
        static Arguments* parse_arguments(int argc, char **argv);

    Arguments()
    {
        this->recursionDesired = false;
        this->reverseQuery = false;
        this->ipv6 = false;
        this->dnsServer = "";
        this->port = 53;
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
                arguments->port = std::stoi(optarg);
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


int main(int argc, char *argv[])
{
    Arguments *arguments = Arguments::parse_arguments(argc, argv);
    std::cout << arguments->ipv6 << "\n";
    std::cout << arguments->port << "\n";
    std::cout << arguments->recursionDesired << "\n"; 
    std::cout << arguments->reverseQuery << "\n"; 
    std::cout << arguments->dnsServer << "\n";
    std::cout << arguments->target << "\n";
}