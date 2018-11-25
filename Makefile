all: main.c
	gcc -Wall -g -lcap -lseccomp main.c -o main

clean:
	rm -f main
