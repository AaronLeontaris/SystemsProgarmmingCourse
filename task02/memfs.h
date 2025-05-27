#ifndef MEMFS_H
#define MEMFS_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <ctime>

#define MAX_FILENAME_LEN 255
#define MAX_FILE_SIZE 512
#define PERSISTENCE_FILE "memfs.img"

enum class NodeType { File, Directory, Symlink };

struct MemFSNode : public std::enable_shared_from_this<MemFSNode> {
    std::string name;
    NodeType type;
    std::string data; // file data or symlink target
    size_t size = 0;
    mode_t mode = 0644;
    uid_t uid;
    gid_t gid;
    time_t atime, mtime, ctime;
    std::weak_ptr<MemFSNode> parent;
    std::map<std::string, std::shared_ptr<MemFSNode>> children; // for directories

    MemFSNode(const std::string& name, NodeType type, mode_t mode, uid_t uid, gid_t gid, std::weak_ptr<MemFSNode> parent);

    std::string to_json() const;
    static std::shared_ptr<MemFSNode> from_json(const std::string& json, std::weak_ptr<MemFSNode> parent);
};

struct MemFS {
    std::shared_ptr<MemFSNode> root;
    MemFS();
    void save();
    void load();
};

extern MemFS memfs;

#endif