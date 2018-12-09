#include <sys/resource.h>

#define MEMORY "536870912" // 500 MB
#define SHARES "256" // 25% of cpu time
#define PIDS "64" // limit child to 16 processes
#define WEIGHT "10" // priority of container
#define LEN 256

struct cgrp_control {
  char control[LEN];
  struct cgrp_setting {
    char name[LEN];
    char value[LEN];
  } **settings;
};

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
