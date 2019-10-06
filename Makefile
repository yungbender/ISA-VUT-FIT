CC=g++
FLAGS=-g -Wall -Werror -pedantic -std=c++11
FILE=dns
OTHER_FILES=dns_header.hpp

all:
	$(CC) $(FLAGS) $(FILE).cpp dns_header.hpp -o $(FILE)
