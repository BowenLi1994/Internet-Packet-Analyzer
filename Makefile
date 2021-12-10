all: panalyzer
CC = g++ -std=c++11  -Wall

panalyzer: panalyzer.cpp
	$(CC) -o panalyzer panalyzer.cpp
clean:
	rm panalyzer
