

#CROSS_COMPILE ?= arm-linux-
CFLAGS ?= -static -g

all:
	$(CROSS_COMPILE)g++ main.cpp $(CFLAGS) -std=c++0x -pthread -o test


clean:
	rm -f *.o test



