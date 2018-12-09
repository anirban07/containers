LIBS=-lcap -lseccomp
all: main.c cgroups.h
	gcc -Wall -g main.c utils.c -o main ${LIBS}

test_utils: test_utils.c utils.c utils.h
	gcc -Wall -g test_utils.c utils.c -o test_utils ${LIBS}
	./test_utils

check: test_utils

clean:
	rm -f main
	rm -f test_utils
	rm -rf test_dest_dir/*
