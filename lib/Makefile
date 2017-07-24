CFLAGS = -g -O2 -Wall -pedantic -ansi
LFLAGS =

vpath %.h ../include/

sniffer.o: sniffer.c snif.h
		gcc -c $< $(CFLAGS) $(LFLAGS)

clean:
		rm -rf *.o
