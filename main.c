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

struct prog {
    char *prog_name;
    char **prog_args;
    char *root_path;
};

int child_func(void *_prog) {
    struct prog *prog = (struct prog *) _prog;
    // int err = setns(prog->mnt_fd, CLONE_NEWNS);
    
    // if (err == -1) {
    //     perror("Child error");
    //     return 0;
    // }
    int err = mount(prog->root_path, prog->root_path, NULL, MS_BIND | MS_REC, NULL);
    if (err) {
        perror("Error");
    }
    err = chdir(prog->root_path);
    if (err) {
        perror("chdir into root error");
    }
    mode_t mask = umask(0);
    err = mkdir("dev", 0755);
    if (err) {
        perror("mkdir dev error");
    }
    err = mount("tmpfs", "dev", "tmpfs", 0, "mode=0755");
    if (err) {
        perror("mount tmpfs error");
    }
    err = mkdir("dev/tmp", 0755);
    if (err) {
        perror("mkdir dev/tmp error");
    }
    umask(mask);
    char buf[128] = {0};
    getcwd(buf, 127);
    printf("pwd: %s\n", buf);
    err = syscall(__NR_pivot_root, ".", "dev");
    if (err) {
        perror("Pivot error");
    }
    err = chdir("/");
    if (err) {
        perror("Chdir error");
    }

    execvp(prog->prog_name, prog->prog_args);
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
    char *prog_args[] = {"bash", NULL};
    char *child_root_path = "child_root";
    
    struct prog prog = {prog_name, prog_args, child_root_path};
    int err = clone(&child_func, stack + STACK_SIZE, flags, &prog);
    if (err == -1) {
      perror("Clone error");
    }

    printf("Parent called clone\n");
    wait(NULL);
    return 0;
}