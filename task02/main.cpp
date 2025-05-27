#include <fuse.h>
#include "memfs.h"

extern struct fuse_operations memfs_oper;

int main(int argc, char *argv[]) {
    memfs.load();
    int res = fuse_main(argc, argv, &memfs_oper, nullptr);
    memfs.save();
    return res;
}