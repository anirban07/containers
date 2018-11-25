all: main.c
	gcc -Wall -g -lcap main.c -o main

clean:
	rm -f main
