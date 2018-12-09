#define _GNU_SOURCE

#include <sched.h>
#include <linux/sched.h>
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
#include <errno.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <seccomp.h>

#include "utils.h"
#include "cgroups.h"

#define DEFAULT_PROG "/bin/bash"
#define DEFAULT_HOSTNAME "cannotbecontained"
#define FD_COUNT 64
#define PATH_LEN 128
#define DEFAULT_CONTAINER_ROOT_TEMPLATE "/tmp/container_root.XXXXXX"
#define DEFAULT_CONTAINER_MT_POINT_TEMPLATE "/tmp/container_tmp.XXXXXX"
#define DEFAULT_OLD_ROOT "/old_root.XXXXXX"
#define DEFAULT_OLD_ROOT_TEMPLATE DEFAULT_CONTAINER_MT_POINT_TEMPLATE DEFAULT_OLD_ROOT

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

struct config {
    char *prog_name;
    char **prog_args;
    char *root_path;
};

// Drops privileged capabilities of the root user
static int capabilities() {
    int privileged[] = {
        // These first three capabilities allow for a process
        // to access the auditing system on the kernel.
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_WRITE,
        // This capability allows the process to prevent the kernel
        // from suspending this process
        CAP_BLOCK_SUSPEND,
        // This capability allows a process to (in theory) read from any
        // inode
        CAP_DAC_READ_SEARCH,
        // This capability allows a process to set root user id's.
        CAP_FSETID,
        // This capability allows a process to lock more memory than it was
        // given.
        CAP_IPC_LOCK,
        // These capabilities can be used to circumvent namespace access.
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        // Prevent the process from creating a new device
        CAP_MKNOD,
        // Prevent the process from setting capabilies of other executables
        CAP_SETFCAP,
        // Prevent the process from altering the system log
        CAP_SYSLOG,
        // Should be obvious why this is bad
        CAP_SYS_ADMIN,
        // Prevent the process from rebooting the system with a different kernel
        CAP_SYS_BOOT,
        // Prevent the process from loading external device modules
        CAP_SYS_MODULE,
        // Prevent the process from setting process priority in scheduling
        CAP_SYS_NICE,
        // Prevent the process from accessing I/O ports
        CAP_SYS_RAWIO,
        // Prevent the process from grabbing more resources than the kernel
        // allows
        CAP_SYS_RESOURCE,
        // Prevent the process from altering the time
        CAP_SYS_TIME,
        // Prevent the process from messing with scheduling alarms
        CAP_WAKE_ALARM,
    };

    int err = 0;
    // Drop the privileged capabilities
    for (int i = 0; i < 20; i++) {
        err = prctl(PR_CAPBSET_DROP, privileged[i], 0, 0, 0);
        BAIL_ON_ERROR(err)
    }

    // Clear the capabilities in the process
    cap_t capabilities = cap_get_proc();
    err = capabilities == NULL;
    BAIL_ON_ERROR(err)
    err = cap_set_flag(capabilities, CAP_INHERITABLE, 20, privileged, CAP_CLEAR);
    BAIL_ON_ERROR(err)
    err = cap_set_proc(capabilities);
    BAIL_ON_ERROR(err)

    cap_free(capabilities);

    printf("=> Updated child's capabilities\n");
error:
    return err;
}

// Drops privileged syscalls
static int syscalls() {
    scmp_filter_ctx ctx = NULL;
    int err = 0;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    err = ctx == NULL;
    BAIL_ON_ERROR(err)

    // Prevent new setguid, setgid executables from being enabled
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID));
    BAIL_ON_ERROR(err);

    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID));
    BAIL_ON_ERROR(err)

    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID));
    BAIL_ON_ERROR(err)
    
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID));
    BAIL_ON_ERROR(err)
    
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID));
    BAIL_ON_ERROR(err);
    
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID));
    BAIL_ON_ERROR(err);

    // Prevent new user namespaces from being created
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,
                SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
    BAIL_ON_ERROR(err)
    
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1,
                SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
    BAIL_ON_ERROR(err)

    // Prevent this process from writing to the terminal
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI));
    BAIL_ON_ERROR(err)

    // Prevent access to the kernel's keyring
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0);
    BAIL_ON_ERROR(err)

    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0);
    BAIL_ON_ERROR(err)
    
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0);
    BAIL_ON_ERROR(err)

    // Prevent ptrace calls
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0);
    BAIL_ON_ERROR(err)

    // Prevent NUMA node assignment
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0);
    BAIL_ON_ERROR(err)

    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0);
    BAIL_ON_ERROR(err)

    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0);
    BAIL_ON_ERROR(err)

    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0);
    BAIL_ON_ERROR(err)

    // Prevent this process from handling page faults
    err = seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0);
    BAIL_ON_ERROR(err)

    // Prevent setuid and setcap from being executed
    err = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0);
    BAIL_ON_ERROR(err)

    err = seccomp_load(ctx);
    BAIL_ON_ERROR(err)

    seccomp_release(ctx);
    printf("=> Filtered child's system calls\n");

error:
    return err;
}

// make root_path the new root.
// need temp mount_dir to pivot root. -- Not sure why
static int mounts(char *root_path) {
    int err = 0;
    err = mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);
    BAIL_ON_ERROR(err)

    char mount_dir[] = DEFAULT_CONTAINER_MT_POINT_TEMPLATE;
    err = mkdtemp(mount_dir) == NULL;
    BAIL_ON_ERROR(err)

    err = mount(root_path, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL);
    BAIL_ON_ERROR(err)

    char inner_mount_dir[] = DEFAULT_OLD_ROOT_TEMPLATE;
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

    err = umount2(old_root_name, MNT_DETACH);
    BAIL_ON_ERROR(err)

    err = rmdir(old_root_name);
    BAIL_ON_ERROR(err)
    
error:
    return err;
}

static int cgroups_and_resources(char* hostname) {
    int err = 0;
    for (struct cgrp_control **group = cgrps; *group; group++) {
        // Create a directory under the hostname of the child
        // for each control group
        char dirpath[PATH_LEN] = {0};
        err = snprintf(dirpath, sizeof(dirpath), "/sys/fs/cgroup/%s/%s", (*group)->control, hostname);
        BAIL_ON_ERROR(err)

        printf("Writing %s cgroup\n", (*group)->control);
        err = mkdir(dirpath, S_IRUSR | S_IWUSR | S_IXUSR);
        BAIL_ON_ERROR(err)

        printf("\tSuccessfully made directory in cgroup\n");
        // Then write the settings for each cgroup
        for (struct cgrp_setting **setting = (*group)->settings; *setting; setting++) {
            char setting_path[PATH_LEN] = {0};
            int fd = 0;
            err = snprintf(setting_path, sizeof(setting_path), "%s/%s", dirpath, (*setting)->name);
            BAIL_ON_ERROR(err)

            fd = open(setting_path, O_WRONLY);
            BAIL_ON_ERROR(fd)
            
            err = write(fd, (*setting)->value, strlen((*setting)->value));
            BAIL_ON_ERROR(err)

            close(fd);
        }
    }

    // Finally, limit the number of new file descriptors using setrlimit
    struct rlimit fd_limit = {
        .rlim_max = FD_COUNT,
        .rlim_cur = FD_COUNT
    };

    err = setrlimit(RLIMIT_NOFILE, &fd_limit);
    BAIL_ON_ERROR(err)

error:
    return err;
}

static int free_cgroups_and_resources(char* hostname) {
    int err = 0;
    for (struct cgrp_control **group = cgrps; *group; group++) {
        char dirpath[PATH_LEN] = {0};
	char taskpath[PATH_LEN] = {0};
	int fd = 0;
	err = snprintf(dirpath, sizeof(dirpath), "/sys/fs/cgroup/%s/%s", (*group)->control, hostname);
	BAIL_ON_ERROR(err)
	
	err = snprintf(taskpath, sizeof(taskpath), "/sys/fs/cgroup/%s/tasks", (*group)->control);
	BAIL_ON_ERROR(err)
	
	fd = open(taskpath, O_WRONLY);
	BAIL_ON_ERROR(fd)

	err = write(fd, "0", 2);
	BAIL_ON_ERROR(err)

	close(fd);

	err = rmdir(dirpath) == 0 ? 0 : -1;
	BAIL_ON_ERROR(err)
    }

error:
    return err;
}

int mount_proc() {
    int err = 0;
    struct stat st = {0};
    if (stat("/proc", &st) == -1) {
        err = mkdir("/proc", 0555);
        BAIL_ON_ERROR(err)
    }
    err = mount("proc", "/proc", "proc", 0, NULL);
    BAIL_ON_ERROR(err)

error:
    return err;
}

int child_func(void *_config) {
    int err = 0;
    struct config *config = (struct config *) _config;

    err = sethostname(DEFAULT_HOSTNAME, strlen(DEFAULT_HOSTNAME));
    BAIL_ON_ERROR(err)

    err = mounts(config->root_path);
    BAIL_ON_ERROR(err)

    err = mount_proc();
    BAIL_ON_ERROR(err)

    err = capabilities();
    BAIL_ON_ERROR(err)

    err = syscalls();
    BAIL_ON_ERROR(err)

    err = execve(config->prog_name, config->prog_args, NULL);
    BAIL_ON_ERROR(err)

error:
    return err;
}

void usage() {
    printf("Usage: ./main [-r root_dir/] [-b base_image/] [CMD [ARG]...]\n");
    exit(1);
}

int main(int argc, char **argv) {
    int option;
    int err;
    char *prog_name;
    char **prog_args = {NULL};
    char *root_dir_path = NULL;
    char *base_image_path = NULL;

    while ((option = getopt(argc, argv, "+r:b:")) != -1) {
        switch(option) {
            case 'r':
                root_dir_path = optarg;
                break;
            case 'b':
                base_image_path = optarg;
                break;
            default:
                usage();
        }
    }

    if (!root_dir_path && !base_image_path) {
        usage();
    }

    if (!root_dir_path) {
        char root_dir_path_arr[] = DEFAULT_CONTAINER_ROOT_TEMPLATE;
        root_dir_path = mkdtemp(root_dir_path_arr);
        if (!root_dir_path) {
            perror("mkdtemp error");
        }
    }

    if (base_image_path) {
        printf("=> Clearing out contents of %s...", root_dir_path);
        fflush(stdout);
        char *rm_format_str = "rm -rf %s/*";
        char rm_command_buf[strlen(rm_format_str) + strlen(root_dir_path)];
        snprintf(rm_command_buf, sizeof(rm_command_buf), rm_format_str, root_dir_path);
        system(rm_command_buf);
        printf("done\n");

        printf("=> Copying base image %s into %s...", base_image_path, root_dir_path);
        fflush(stdout);
        char *cp_format_str = "cp -r %s/* %s";
        char cp_command_buf[strlen(cp_format_str) + strlen(base_image_path) + strlen(root_dir_path)];
        snprintf(cp_command_buf, sizeof(cp_command_buf), cp_format_str, base_image_path, root_dir_path);
        system(cp_command_buf);
        printf("done\n");
    }

    if (argc <= optind) {
        prog_name = DEFAULT_PROG;
    } else {
        prog_name = argv[optind];
        prog_args = &argv[optind];
    }

    int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWCGROUP | SIGCHLD;
    const size_t STACK_SIZE = 1 << 20;
    uint8_t *stack = (uint8_t *) malloc(STACK_SIZE);
    if (!stack) {
        return 1;
    }

    if (cgroups_and_resources(DEFAULT_HOSTNAME)) {
      return 1;
    }
    
    struct config config = {prog_name, prog_args, root_dir_path};
    err = clone(&child_func, stack + STACK_SIZE, flags, &config);
    if (err == -1) {
      perror("Clone error");
    }

    wait(NULL);
    free(stack);
    free_cgroups_and_resources(DEFAULT_HOSTNAME);
    return 0;
}
