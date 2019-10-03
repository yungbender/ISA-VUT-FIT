// Project for subject Computer Communications and Networks
// TCP/UDP port scanner
// Author: Tomáš Sasák
// BUT FIT 2019

#include <iostream> // cout
#include <string> // string
#include <vector> // vectors
#include <cstdlib> // stof, stoi
#include <mutex> // mutex
#include <getopt.h> // getopt_long_only
#include <sys/socket.h> // socket
#include <arpa/inet.h> // inet_ntop, inet_pton
#include <regex.h> // regex
#include <netdb.h> // getnameinfo
#include <string.h> // strcmp
#include <netinet/ip.h> // ip header
#include <netinet/udp.h> // udp header
#include <netinet/tcp.h> // tcp header  
#include <unistd.h> // sleep, close
#include <ifaddrs.h> // getifaddrs
#include <net/if.h> // IFF_UP macro for interfaces
