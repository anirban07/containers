#include "utils.h"

void test_copy_dir(char *dest, char *src) {
    copy_dir(dest, src);
}

int main() {
    char *src = "test_src_dir";
    char *dest = "test_dest_dir";
    test_copy_dir(dest, src);
}