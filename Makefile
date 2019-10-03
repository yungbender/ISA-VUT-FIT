CC=g++
FLAGS=-g -Wall -Werror -pedantic -std=c++11
FILE=dns

all:
	$(CC) $(FLAGS) $(FILE).cpp -o $(FILE)
