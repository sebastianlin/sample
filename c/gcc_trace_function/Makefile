

#CROSS_COMPILE ?= arm-linux-
CFLAGS += -finstrument-functions



all:
	$(CROSS_COMPILE)gcc $(CFLAGS) main.c -o test -static -g



clean:
	rm *.o test



