#pragma once
#include <memory>
#include <map>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctime>

// Node types
enum class MemNodeType { File, Directory, Symlink };

// Node in the in-memory FS
struct MemNode {
    std::string name;
    MemNodeType type;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    size_t size;
    std::vector<char> data;        // for files
    std::string symlink_target;    // for symlinks
    std::map<std::string, std::shared_ptr<MemNode>> children; // for directories

    MemNode *parent;
    time_t atime, mtime, ctime;

    MemNode(const std::string& name, MemNodeType type, mode_t mode, MemNode *parent = nullptr);
};

void memfs_init();
std::shared_ptr<MemNode> memfs_lookup(const std::string& path);
std::shared_ptr<MemNode> memfs_parent(const std::string& path, std::string &child);