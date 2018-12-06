#define COPY_BUF_SIZE 512

#define BAIL() \
    perror(NULL); \
    printf("%d\n", errno); \
    goto error; \

#define BAIL_ON_ERROR(err) \
    if ((err) == -1) { \
        BAIL() \
    }


// Copy contents of src directory into dest directory recursively
int copy_dir(char *dest, char *src);

int copy_file(char *src, char *dest);


