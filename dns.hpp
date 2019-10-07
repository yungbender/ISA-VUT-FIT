// Project for subject Computer Communications and Networks
// TCP/UDP port scanner
// Author: Tomáš Sasák
// BUT FIT 2019

#include <iostream> // cout
#include <string> // string
#include <vector> // vectors
#include <cstdlib> // stof, stoi
#include <unistd.h> // getopt
#include <sys/socket.h> // socket
#include <string.h> // strcmp
#include <netdb.h> // getaddrinfo
#include <arpa/inet.h> // ntohs