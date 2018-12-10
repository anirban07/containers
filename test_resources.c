#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

// Tests cgroup limits and fd count

#define MEMORY_LIMIT 1048576
#define PID_LIMIT 10
#define FD_LIMIT 64

void test_memory() {
  // Attempt to calloc more memory
  // than is allowed.
  
  printf("Test Memory Allocation\n");
  
  printf("Attempting to calloc %d bytes of memory\n", MEMORY_LIMIT - MEMORY_LIMIT / 3);
  char* memory = (char*)calloc(MEMORY_LIMIT - MEMORY_LIMIT / 3, sizeof(char));
  assert(memory != NULL);

  sleep(10);
  printf("Locking memory in process\n");
  int err = mlockall(MCL_CURRENT | MCL_FUTURE);
  if (err == -1) {
    perror("mlockall() failed");
    printf("Errno %d\n", errno);
    free(memory);
  }

  printf("Attempting to calloc %d bytes of memory\n", MEMORY_LIMIT - MEMORY_LIMIT / 3);
  char* memory2 = (char*)calloc(MEMORY_LIMIT - MEMORY_LIMIT / 3, sizeof(char));
  sleep(10);

  munlockall();
  if (memory2 == NULL) {
    perror("Test Memory Allocation");
    printf("Test succeeded\n");
    free(memory);
  } else {
    free(memory);
    free(memory2);
    fprintf(stderr, "FAIL: Process able to allocate more memory than allowed.\n");
  }
}

void test_pids() {
  printf("Creating %d children processes that should succeed\n", PID_LIMIT);
  for (int i = 0; i < PID_LIMIT; i++) {
    int pid = fork();
    if (pid == 0) {
      sleep(60);
      return;
    } else if (pid == -1) {
      printf("Failed to create child process %d\n", i);
      perror(NULL);
      return;
    }
  }

  printf("Creating an extra process. This should fail.\n");
  int pid = fork();
  assert(pid == -1);
  perror(NULL);
}

void test_fds() {
  printf("Opening %d unique files that should succeed\n", FD_LIMIT - 3);
  int fds[FD_LIMIT - 3];
  char filepath[32] = {0};
  for (int i = 0; i < FD_LIMIT - 3; i++) {
    snprintf(filepath, sizeof(filepath), "%s_%d.txt", "test_file", i + 1);
    fds[i] = open(filepath, O_WRONLY | O_CREAT);

    if (fds[i] == -1) {
      perror(NULL);
      for (int j = 0; j < i; j++) {
        close(fds[j]);
      }
      return;
    }
  }

  printf("Opening an extra file\n");
  int fd = open("i_should_not_exist.txt", O_WRONLY | O_CREAT);
  if (fd == -1) {
    printf("Test succeeded!\n");
  } else {
    printf("Test failed\n");
    close(fd);
  }

  for (int i = 0; i < FD_LIMIT - 3; i++) {
    close(fds[i]);
  }
}


int main() {
  // test_memory();
  // test_pids();
  // test_fds();
  return 0;
}