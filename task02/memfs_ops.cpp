#include "memfs.h"
#include <fuse.h>
#include <errno.h>
#include <cstring>
#include <string>
#include <memory>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>

static std::vector<std::string> split_path(const char *path) {
    std::vector<std::string> elems;
    std::string s(path);
    size_t pos = 0;
    while ((pos = s.find('/')) != std::string::npos) {
        if (pos != 0) elems.push_back(s.substr(0, pos));
        s = s.substr(pos + 1);
    }
    if (!s.empty()) elems.push_back(s);
    return elems;
}

// Find node by path
static std::shared_ptr<MemFSNode> find_node(const char *path) {
    if (strcmp(path, "/") == 0) return memfs.root;
    auto parts = split_path(path);
    auto curr = memfs.root;
    for (const auto& p : parts) {
        if (curr->type != NodeType::Directory) return nullptr;
        if (curr->children.count(p) == 0) return nullptr;
        curr = curr->children[p];
    }
    return curr;
}
// Find parent node of a path
static std::shared_ptr<MemFSNode> find_parent(const char *path, std::string& leaf) {
    auto parts = split_path(path);
    if (parts.empty()) return nullptr;
    leaf = parts.back();
    parts.pop_back();
    auto curr = memfs.root;
    for (const auto& p : parts) {
        if (curr->type != NodeType::Directory) return nullptr;
        if (curr->children.count(p) == 0) return nullptr;
        curr = curr->children[p];
    }
    return curr;
}

// normale Fuse callbasd

static int memfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *) {
    memset(stbuf, 0, sizeof(struct stat));
    auto node = find_node(path);
    if (!node) return -ENOENT;
    if (node->type == NodeType::Directory) {
        stbuf->st_mode = S_IFDIR | node->mode;
        stbuf->st_nlink = 2;
    } else if (node->type == NodeType::File) {
        stbuf->st_mode = S_IFREG | node->mode;
        stbuf->st_nlink = 1;
        stbuf->st_size = node->size;
    } else if (node->type == NodeType::Symlink) {
        stbuf->st_mode = S_IFLNK | node->mode;
        stbuf->st_nlink = 1;
        stbuf->st_size = node->data.size();
    }
    stbuf->st_uid = node->uid;
    stbuf->st_gid = node->gid;
    stbuf->st_atime = node->atime;
    stbuf->st_mtime = node->mtime;
    stbuf->st_ctime = node->ctime;
    return 0;
}

static int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    auto node = find_node(path);
    if (!node || node->type != NodeType::Directory) return -ENOENT;
    filler(buf, ".", nullptr, 0);
    filler(buf, "..", nullptr, 0);
    for (const auto& [name, child] : node->children) {
        filler(buf, name.c_str(), nullptr, 0);
    }
    return 0;
}

static int memfs_mkdir(const char *path, mode_t mode) {
    std::string leaf;
    auto parent = find_parent(path, leaf);
    if (!parent || parent->type != NodeType::Directory) return -ENOENT;
    if (leaf.size() > MAX_FILENAME_LEN) return -ENAMETOOLONG;
    if (parent->children.count(leaf)) return -EEXIST;
    auto node = std::make_shared<MemFSNode>(leaf, NodeType::Directory, mode, fuse_get_context()->uid, fuse_get_context()->gid, parent);
    parent->children[leaf] = node;
    memfs.save();
    return 0;
}

static int memfs_mknod(const char *path, mode_t mode, dev_t) {
    std::string leaf;
    auto parent = find_parent(path, leaf);
    if (!parent || parent->type != NodeType::Directory) return -ENOENT;
    if (leaf.size() > MAX_FILENAME_LEN) return -ENAMETOOLONG;
    if (parent->children.count(leaf)) return -EEXIST;
    auto node = std::make_shared<MemFSNode>(leaf, NodeType::File, mode, fuse_get_context()->uid, fuse_get_context()->gid, parent);
    parent->children[leaf] = node;
    memfs.save();
    return 0;
}

static int memfs_create(const char *path, mode_t mode, struct fuse_file_info *) {
    return memfs_mknod(path, mode, 0);
}

static int memfs_open(const char *path, struct fuse_file_info *) {
    auto node = find_node(path);
    if (!node || node->type != NodeType::File) return -ENOENT;
    return 0;
}

static int memfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *) {
    auto node = find_node(path);
    if (!node || node->type != NodeType::File) return -ENOENT;
    if ((size_t)offset >= node->size) return 0;
    size_t to_read = std::min(size, node->size - (size_t)offset);
    memcpy(buf, node->data.data() + offset, to_read);
    node->atime = time(NULL);
    return to_read;
}

static int memfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *) {
    auto node = find_node(path);
    if (!node || node->type != NodeType::File) return -ENOENT;
    if (offset > MAX_FILE_SIZE) return -EFBIG;
    size_t to_write = std::min(size, (size_t)(MAX_FILE_SIZE - offset));
    if ((size_t)offset + to_write > node->data.size()) node->data.resize(offset + to_write);
    memcpy(&node->data[0] + offset, buf, to_write);
    node->size = node->data.size();
    node->mtime = time(NULL);
    node->ctime = node->mtime;
    memfs.save();
    return to_write;
}

static int memfs_symlink(const char *from, const char *to) {
    std::string leaf;
    auto parent = find_parent(to, leaf);
    if (!parent || parent->type != NodeType::Directory) return -ENOENT;
    if (leaf.size() > MAX_FILENAME_LEN) return -ENAMETOOLONG;
    if (parent->children.count(leaf)) return -EEXIST;
    auto node = std::make_shared<MemFSNode>(leaf, NodeType::Symlink, 0777, fuse_get_context()->uid, fuse_get_context()->gid, parent);
    node->data = from;
    node->size = node->data.size();
    parent->children[leaf] = node;
    memfs.save();
    return 0;
}

static int memfs_readlink(const char *path, char *buf, size_t size) {
    auto node = find_node(path);
    if (!node || node->type != NodeType::Symlink) return -ENOENT;
    strncpy(buf, node->data.c_str(), size - 1);
    buf[size - 1] = '\0';
    return 0;
}

// -
struct fuse_operations memfs_oper = {
    .getattr = memfs_getattr,
    .readdir = memfs_readdir,
    .mkdir   = memfs_mkdir,
    .mknod   = memfs_mknod,
    .create  = memfs_create,
    .open    = memfs_open,
    .read    = memfs_read,
    .write   = memfs_write,
    .symlink = memfs_symlink,
    .readlink= memfs_readlink,
};