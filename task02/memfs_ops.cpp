#include "memfs.hpp"
#include <fuse.h>
#include <cstring>
#include <errno.h>
#include <sys/stat.h>

// Helper to fill struct stat from MemNode
static void set_stat(std::shared_ptr<MemNode> node, struct stat* st) {
    memset(st, 0, sizeof(struct stat));
    st->st_uid = node->uid;
    st->st_gid = node->gid;
    st->st_mode = node->mode;
    st->st_nlink = (node->type == MemNodeType::Directory) ? 2 + node->children.size() : 1;
    st->st_size = node->size;
    st->st_atime = node->atime;
    st->st_mtime = node->mtime;
    st->st_ctime = node->ctime;
}

// getattr
extern "C" int memfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *) {
    auto node = memfs_lookup(path);
    if (!node) return -ENOENT;
    set_stat(node, stbuf);
    return 0;
}

// readdir
extern "C" int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t, struct fuse_file_info *) {
    auto node = memfs_lookup(path);
    if (!node || node->type != MemNodeType::Directory) return -ENOENT;
    filler(buf, ".", nullptr, 0);
    filler(buf, "..", nullptr, 0);
    for (const auto& [name, child] : node->children) {
        filler(buf, name.c_str(), nullptr, 0);
    }
    return 0;
}

// mkdir
extern "C" int memfs_mkdir(const char *path, mode_t mode) {
    std::string child;
    auto parent = memfs_parent(path, child);
    if (!parent || parent->type != MemNodeType::Directory) return -ENOENT;
    if (child.length() > MAX_FILENAME_LEN) return -ENAMETOOLONG;
    if (parent->children.count(child)) return -EEXIST;
    auto newdir = std::make_shared<MemNode>(child, MemNodeType::Directory, (mode & 0777) | S_IFDIR, parent.get());
    parent->children[child] = newdir;
    parent->mtime = std::time(0);
    return 0;
}

// mknod (for files)
extern "C" int memfs_mknod(const char *path, mode_t mode, dev_t) {
    std::string child;
    auto parent = memfs_parent(path, child);
    if (!parent || parent->type != MemNodeType::Directory) return -ENOENT;
    if (child.length() > MAX_FILENAME_LEN) return -ENAMETOOLONG;
    if (parent->children.count(child)) return -EEXIST;
    if (!S_ISREG(mode)) return -EINVAL;
    auto newfile = std::make_shared<MemNode>(child, MemNodeType::File, (mode & 0777) | S_IFREG, parent.get());
    parent->children[child] = newfile;
    parent->mtime = std::time(0);
    return 0;
}

// open (just check existence)
extern "C" int memfs_open(const char *path, struct fuse_file_info *) {
    auto node = memfs_lookup(path);
    if (!node || node->type != MemNodeType::File) return -ENOENT;
    return 0;
}

// read
extern "C" int memfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *) {
    auto node = memfs_lookup(path);
    if (!node || node->type != MemNodeType::File) return -ENOENT;
    if (offset >= node->size) return 0;
    size_t to_read = std::min(size, node->size - offset);
    memcpy(buf, node->data.data() + offset, to_read);
    node->atime = std::time(0);
    return to_read;
}

// write
extern "C" int memfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *) {
    auto node = memfs_lookup(path);
    if (!node || node->type != MemNodeType::File) return -ENOENT;
    if (offset > MAX_FILE_SIZE) return -EFBIG;
    size_t to_write = std::min(size, MAX_FILE_SIZE - offset);
    if (offset + to_write > node->data.size())
        node->data.resize(offset + to_write, 0);
    memcpy(node->data.data() + offset, buf, to_write);
    node->size = std::max(node->size, offset + to_write);
    node->mtime = std::time(0);
    node->ctime = std::time(0);
    return to_write;
}

// create (open + mknod)
extern "C" int memfs_create(const char *path, mode_t mode, struct fuse_file_info *) {
    return memfs_mknod(path, mode, 0);
}

// symlink
extern "C" int memfs_symlink(const char *target, const char *linkpath) {
    std::string child;
    auto parent = memfs_parent(linkpath, child);
    if (!parent || parent->type != MemNodeType::Directory) return -ENOENT;
    if (child.length() > MAX_FILENAME_LEN) return -ENAMETOOLONG;
    if (parent->children.count(child)) return -EEXIST;
    auto node = std::make_shared<MemNode>(child, MemNodeType::Symlink, S_IFLNK | 0777, parent.get());
    node->symlink_target = target;
    node->size = strlen(target);
    parent->children[child] = node;
    parent->mtime = std::time(0);
    return 0;
}

// readlink
extern "C" int memfs_readlink(const char *path, char *buf, size_t size) {
    auto node = memfs_lookup(path);
    if (!node || node->type != MemNodeType::Symlink) return -EINVAL;
    size_t len = std::min(size - 1, node->symlink_target.length());
    memcpy(buf, node->symlink_target.c_str(), len);
    buf[len] = '\0';
    node->atime = std::time(0);
    return 0;
}

// unlink (delete file)
extern "C" int memfs_unlink(const char *path) {
    std::string child;
    auto parent = memfs_parent(path, child);
    if (!parent || parent->type != MemNodeType::Directory) return -ENOENT;
    auto it = parent->children.find(child);
    if (it == parent->children.end() || it->second->type == MemNodeType::Directory) return -ENOENT;
    parent->children.erase(it);
    parent->mtime = std::time(0);
    return 0;
}

// rmdir (delete empty directory)
extern "C" int memfs_rmdir(const char *path) {
    std::string child;
    auto parent = memfs_parent(path, child);
    if (!parent || parent->type != MemNodeType::Directory) return -ENOENT;
    auto it = parent->children.find(child);
    if (it == parent->children.end() || it->second->type != MemNodeType::Directory) return -ENOENT;
    if (!it->second->children.empty()) return -ENOTEMPTY;
    parent->children.erase(it);
    parent->mtime = std::time(0);
    return 0;
}