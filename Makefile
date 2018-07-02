CC = g++
CFLAGS = -Wall -O0 -std=c++11 -g -o

meltdown:
	${CC} ${CFLAGS} meltdown meltdown.cpp

clean:
	rm -rf *.o
	rm -rf meltdown