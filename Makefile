CFLAGS= -Wall -Wextra
MODULES=sslsniff.c functions.c

make:
	gcc -g $(CFLAGS) $(MODULES) -o sslsniff -lpcap -lpthread

debug:
	gcc -g $(CFLAGS) $(MODULES) -o sslsniff -lpcap -lpthread -D DEBUG

clean:
	rm sslsniff

run:
	./sslsniff -i wlp2s0 -r test.pcapng

run_s:
	./sslsniff -r test_short.pcapng

