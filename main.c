#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <syscall.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

#define BAIL_ON_ERROR(err) \
    if ((err) == -1) { \
        perror(NULL); \
        printf("%d\n", errno); \
        return -1; \
    }

struct config {
    char *prog_name;
    char **prog_args;
    char *root_path;
};

int child_func(void *_config) {
    int err = 0;
    struct config *config = (struct config *) _config;

    err = mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);
    BAIL_ON_ERROR(err)

    char mount_dir[] = "/tmp/container_tmp.XXXXXX";
    err = mkdtemp(mount_dir) == NULL;
    BAIL_ON_ERROR(err)

    err = mount(config->root_path, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL);
    BAIL_ON_ERROR(err)

    char inner_mount_dir[] = "/tmp/container_tmp.XXXXXX/old_root.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    err = mkdtemp(inner_mount_dir) == NULL;
    BAIL_ON_ERROR(err)

    err = syscall(SYS_pivot_root, mount_dir, inner_mount_dir);
    BAIL_ON_ERROR(err)

    err = chdir("/");
    BAIL_ON_ERROR(err)

    char *old_root_name = basename(inner_mount_dir);
    char old_root[sizeof(inner_mount_dir) + 1] = { '/' };
    strcpy(&old_root[1], old_root_name);

    // printf("Calling exec\n");
    // char buf[128];
    // getcwd(buf, 127);
    // printf("Current working directory: %s\n", buf);

    // struct dirent *de;  // Pointer for directory entry 
  
    // // opendir() returns a pointer of DIR type.  
    // DIR *dr = opendir("."); 
  
    // if (dr == NULL)  // opendir returns NULL if couldn't open directory 
    // { 
    //     printf("Could not open current directory" ); 
    //     return 0; 
    // } 
  
    // // Refer http://pubs.opengroup.org/onlinepubs/7990989775/xsh/readdir.html 
    // // for readdir() 
    // while ((de = readdir(dr)) != NULL) 
    //         printf("%s\n", de->d_name); 
  
    // closedir(dr);     

    err = execve(config->prog_name, config->prog_args, NULL);
    BAIL_ON_ERROR(err)
    return 0;
}

int main() {
    int flags = CLONE_NEWPID | CLONE_NEWNS | SIGCHLD;
    const size_t STACK_SIZE = 1 << 20;
    uint8_t *stack = (uint8_t *) malloc(STACK_SIZE);
    if (!stack) {
        return 1;
    }

    printf("Parent calling clone\n");
    char *prog_name = "/bin/bash";
    char *prog_args[] = {"/bin/bash", NULL};
    char *child_root_path = "child_root";
    
    struct config config = {prog_name, prog_args, child_root_path};
    int err = clone(&child_func, stack + STACK_SIZE, flags, &config);
    if (err == -1) {
      perror("Clone error");
    }

    printf("Parent called clone\n");
    wait(NULL);
    return 0;
}