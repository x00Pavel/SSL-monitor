CFLAGS= -Wall -Wextra
MODULES=sslsniff.c functions.c

make:
	gcc $(CFLAGS) $(MODULES) -o sslsniff -lpcap -lpthread

clean:
	rm sslsniff

run:
	./sslsniff -i wlp2s0 -r test.pcapng

run_s:
	./sslsniff -r test_short.pcapng

dev:
	gcc $(CFLAGS) $(MODULES) -o sslsniff -lpcap -lpthread -D DEBUG