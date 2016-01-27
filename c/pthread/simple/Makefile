

#CROSS_COMPILE ?= arm-linux-
CFLAGS ?= -static -g

all:
	$(CROSS_COMPILE)gcc main.c $(CFLAGS) -pthread -o test


clean:
	rm -f *.o test



