#define _GNU_SOURCE

#include "utils.h"

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
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <seccomp.h>

#define DEFAULT_PROG "/bin/bash"
#define MEMORY "536870912" // 500 MB
#define SHARES "256" // 25% of cpu time
#define PIDS "16" // limit child to 16 processes
#define WEIGHT "50" // priority of container
#define FD_COUNT 64 

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

struct config {
    char *prog_name;
    char **prog_args;
    char *root_path;
};

struct cgrp_control {
  char control[256];
  struct cgrp_setting {
    char name[256];
    char value[256];
  } **settings;
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

static int mounts(struct config *config) {
    int err = 0;
    err = mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);
    BAIL_ON_ERROR(err)

    char mount_dir[] = "/tmp/container_tmp.XXXXXX";
    err = mkdtemp(mount_dir) == NULL;
    BAIL_ON_ERROR(err)
    printf("=> Child's root directory: %s\n", mount_dir);

    err = mount(config->root_path, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL);
    BAIL_ON_ERROR(err)

    char inner_mount_dir[] = "/tmp/container_tmp.XXXXXX/old_root.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    err = mkdtemp(inner_mount_dir) == NULL;
    BAIL_ON_ERROR(err)
    printf("made innter mount dir\n");

    err = syscall(SYS_pivot_root, mount_dir, inner_mount_dir);
    BAIL_ON_ERROR(err)
    printf("pivoted root\n");

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

static int cgroups_and_resources() {
  struct cgrp_setting add_to_tasks = {
    .name = "tasks",
    .value = "0"
  };

  struct cgrp_control *cgrps[] = {
    & (struct cgrp_control) {
      .control = "memory",
      .settings = (struct cgrp_setting *[]) {
	& (struct cgrp_setting) {
	  .name = "memory.limit_in_bytes",
	  .value = MEMORY
	},
	& (struct cgrp_setting) {
	  .name = "memory.kmem.limit_in_bytes",
	  .value = MEMORY
	},
	&add_to_tasks,
	NULL
      }
    },
    & (struct cgrp_control) {
      .control = "cpu",
      .settings = (struct cgrp_setting *[]) {
	& (struct cgrp_setting) {
	  .name = "cpu.shares",
	  .value = SHARES
	},
	&add_to_tasks,
	NULL
      }
    },
    & (struct cgrp_control) {
      .control = "pids",
      .settings = (struct cgrp_setting *[]) {
	& (struct cgrp_setting) {
	  .name = "pids.max",
	  .value = PIDS
	},
	&add_to_tasks,
	NULL
      }
    },
    & (struct cgrp_control) {
      .control = "blkio",
      .settings = (struct cgrp_setting *[]) {
	& (struct cgrp_setting) {
	  .name = "blkio.weight",
	  .value = WEIGHT
	},
	&add_to_tasks,
	NULL
      }
    },
    NULL
  };

  return 0;
}

int child_func(void *_config) {
    int err = 0;
    struct config *config = (struct config *) _config;

    err = mounts(config);
    BAIL_ON_ERROR(err)

    err = capabilities();
    BAIL_ON_ERROR(err);

    err = syscalls();
    BAIL_ON_ERROR(err)

    err = execve(config->prog_name, config->prog_args, NULL);
    BAIL_ON_ERROR(err)

error:
    return err;
}

void usage() {
    printf("Usage: ./main DIR [CMD [ARG]...]\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage();
        exit(1);
    }
    char *child_root_path = argv[1];

    char *prog_name = DEFAULT_PROG;
    char **prog_args = {NULL};
    if (argc >= 3) {
        prog_name = argv[2];
        prog_args = &argv[2];
    }

    int flags = CLONE_NEWPID | CLONE_NEWNS | SIGCHLD;
    const size_t STACK_SIZE = 1 << 20;
    uint8_t *stack = (uint8_t *) malloc(STACK_SIZE);
    if (!stack) {
        return 1;
    }
    
    struct config config = {prog_name, prog_args, child_root_path};
    int err = clone(&child_func, stack + STACK_SIZE, flags, &config);
    if (err == -1) {
      perror("Clone error");
    }

    wait(NULL);
    return 0;
}
