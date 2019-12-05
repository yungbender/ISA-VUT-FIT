CC=g++
FLAGS=-Wall -Werror -pedantic -std=c++11
FILE=dns
COMPILE_FILES=dns.cpp dns_answer.hpp dns_header.hpp dns_question.hpp record_types.hpp soa_header.hpp

all:
	$(CC) $(FLAGS) $(COMPILE_FILES) -o $(FILE)
