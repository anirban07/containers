LIBS=-lcap -lseccomp
all: main.c
	gcc -Wall -g main.c -o main ${LIBS}

clean:
	rm -f main
