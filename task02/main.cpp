#include "memfs.hpp"
#include <fuse.h>
#include <cstring>
#include <cstdio>

// Forward declarations for FUSE callbacks
extern "C" {
    int memfs_getattr(const char *, struct stat *, struct fuse_file_info *);
    int memfs_readdir(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);
    int memfs_mkdir(const char *, mode_t);
    int memfs_mknod(const char *, mode_t, dev_t);
    int memfs_open(const char *, struct fuse_file_info *);
    int memfs_read(const char *, char *, size_t, off_t, struct fuse_file_info *);
    int memfs_write(const char *, const char *, size_t, off_t, struct fuse_file_info *);
    int memfs_create(const char *, mode_t, struct fuse_file_info *);
    int memfs_symlink(const char *, const char *);
    int memfs_readlink(const char *, char *, size_t);
    int memfs_unlink(const char *);
    int memfs_rmdir(const char *);
}

static struct fuse_operations memfs_oper = {
    .getattr = memfs_getattr,
    .readdir = memfs_readdir,
    .mkdir = memfs_mkdir,
    .mknod = memfs_mknod,
    .open = memfs_open,
    .read = memfs_read,
    .write = memfs_write,
    .create = memfs_create,
    .symlink = memfs_symlink,
    .readlink = memfs_readlink,
    .unlink = memfs_unlink,
    .rmdir = memfs_rmdir,
};

int main(int argc, char *argv[]) {
    memfs_init();
    return fuse_main(argc, argv, &memfs_oper, nullptr);
}