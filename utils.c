#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>

// Returns a path of the form "base_path/dir_name"
// Caller responsible for freeing returned char *
char *join_path(char *base_path, char *name) {
    size_t base_path_len = strlen(base_path);
    size_t name_len = strlen(name);
    size_t final_path_len = base_path_len + 1 + name_len;
    char *path = (char *) malloc(final_path_len + 1);
    if (!path) {
        fprintf(stderr, "malloc error\n");
        return NULL;
    }
    memcpy(path, base_path, strlen(base_path));
    path[base_path_len] = '/';
    memcpy(path + base_path_len + 1, name, name_len);
    path[final_path_len] = '\0';
    return path;
}

// Copies file specified by src into dest directory
// Overwrites existing file, or creates new file
int copy_file(char *src, char *dest) {
    int err = 0;
    char read_buf[COPY_BUF_SIZE];
    size_t num_read;
    FILE *src_file = fopen(src, "r");
    if (!src_file) {
        err = -1;
        BAIL()
    }
    char *file_name = basename(src);
    char *dest_file_path = join_path(dest, file_name);
    FILE *dest_file = fopen(dest_file_path, "w");
    free(dest_file_path);
    if (!dest_file) {
        err = -1;
        BAIL()
    }

    while ((num_read = fread(read_buf, 1, COPY_BUF_SIZE, src_file)) != 0) {
        fwrite(read_buf, 1, num_read, dest_file);
    }
    fclose(src_file);
    fclose(dest_file);

error:
    return err;
}

static int copy_recursive(char *dest, char *src) {
    int err = 0;
    struct stat src_path_stat;
    
    err = stat(src, &src_path_stat);
    BAIL_ON_ERROR(err)


    if (S_ISDIR(src_path_stat.st_mode)) {
        char *dir_name = basename(src);
        char *dest_dir_path = join_path(dest, dir_name);

        // mode_t mask = umask(0);
        // err = mkdir(dest_dir_path, mask);
        // umask(mask);
        err = mkdir(dest_dir_path, S_IRUSR | S_IWUSR | S_IXUSR);

        err = copy_dir(dest_dir_path, src);
        free(dest_dir_path);
        BAIL_ON_ERROR(err)
    } else if (S_ISREG(src_path_stat.st_mode)) {
        err = copy_file(src, dest);
        BAIL_ON_ERROR(err)
    } else {
        fprintf(stderr, "%s is not a regular file or directory\n", src);
        return 0;
    }

error:
    return err;
}

// Copy contents of src directory into dest directory recursively
int copy_dir(char *dest, char *src) {
    int err = 0;
    struct stat src_path_stat;
    
    err = stat(src, &src_path_stat);
    BAIL_ON_ERROR(err)

    DIR *src_dir = opendir(src);
    if (!src_dir) {
        err = -1;
        BAIL()
    }
    struct dirent *ent;
    while ((ent = readdir(src_dir)) != NULL) {
        if (!strncmp(ent->d_name, ".", 1) || !strncmp(ent->d_name, "..", 2)) {
            continue;
        }
        char *new_src = join_path(src, ent->d_name);
        err = copy_recursive(dest, new_src);
        free(new_src);
        BAIL_ON_ERROR(err)
    }

error:
    closedir(src_dir);
    return err;
}
