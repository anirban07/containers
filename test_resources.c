#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>
// Tests cgroup limits and fd count

#define MEMORY_LIMIT 1048576

int main() {
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
    return 1;
  }

  printf("Attempting to calloc %d bytes of memory\n", MEMORY_LIMIT - MEMORY_LIMIT / 3);
  char* memory2 = (char*)calloc(MEMORY_LIMIT - MEMORY_LIMIT / 3, sizeof(char));
  sleep(10);

  munlockall();
  if (memory2 == NULL) {
    perror("Test Memory Allocation");
    printf("Test succeeded\n");
    free(memory);
    return 0;
  } else {
    free(memory);
    free(memory2);
    fprintf(stderr, "FAIL: Process able to allocate more memory than allowed.\n");
    return 1;
  }
}
