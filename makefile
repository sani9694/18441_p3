CC = gcc
ARGS = -g -Wall -O2 -I .

all: vodserver echoclient new_packet

vodserver: vodserver.c
	$(CC) $(ARGS) -o vodserver vodserver.c

echoclient: echoclient.c
	$(CC) $(ARGS) -o echoclient echoclient.c

new_packet: new_packet.c
	$(CC) $(ARGS) -o new_packet new_packet.c

clean:
	rm -f *.o vodserver echoclient new_packet *~
