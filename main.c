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
#include <sys/prctl.h>
#include <sys/capability.h>

#define BAIL_ON_ERROR(err) \
    if ((err) == -1) { \
        perror(NULL); \
        printf("%d\n", errno); \
        return -1; \
    }

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

struct config {
    char *prog_name;
    char **prog_args;
    char *root_path;
};


// Drops privileged capabilities of the root user
static int capabilities();

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

    err = capabilities();
    BAIL_ON_ERROR(err);

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
    char *prog_name = "./test_script";
    char *prog_args[] = {"./test_script", NULL};
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

    printf("Finished managing child process capabilities\n");
    return 0;
}