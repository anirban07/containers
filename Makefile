all: main.c
	gcc -Wall -g main.c -o main

clean:
	rm -f main
