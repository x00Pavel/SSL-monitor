CFLAGS= -Wall -Wextra
MODULES=sslsniff.c functions.c

make:
	gcc $(CFLAGS) $(MODULES) -o sslsniff -lpcap
	make run

clean:
	rm sslsniff

run:
	./sslsniff -i iface -r test.pcapng

