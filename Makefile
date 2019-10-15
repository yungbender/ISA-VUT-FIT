CC=g++
FLAGS=-g -Wall -Werror -pedantic -std=c++11
FILE=dns
COMPILE_FILES=dns.cpp record_types.hpp

all:
	$(CC) $(FLAGS) $(COMPILE_FILES) -o $(FILE)
