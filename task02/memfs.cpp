#include "memfs.hpp"
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <algorithm>
#include <iostream>

#define MAX_FILENAME_LEN 255
#define MAX_FILE_SIZE 512

static std::shared_ptr<MemNode> root;

MemNode::MemNode(const std::string& name, MemNodeType type, mode_t mode, MemNode *parent)
    : name(name), type(type), mode(mode), uid(getuid()), gid(getgid()), size(0),
      parent(parent), atime(std::time(0)), mtime(std::time(0)), ctime(std::time(0)) {}

void memfs_init() {
    root = std::make_shared<MemNode>("/", MemNodeType::Directory, 0755, nullptr);
}

static std::vector<std::string> split_path(const std::string &path) {
    std::vector<std::string> result;
    size_t start = 0, end = 0;
    while ((end = path.find('/', start)) != std::string::npos) {
        if (end != start)
            result.emplace_back(path.substr(start, end - start));
        start = end + 1;
    }
    if (start < path.size())
        result.emplace_back(path.substr(start));
    return result;
}

std::shared_ptr<MemNode> memfs_lookup(const std::string& path) {
    if (path == "/" || path.empty()) return root;
    auto comps = split_path(path);
    auto node = root;
    for (const auto& comp : comps) {
        auto it = node->children.find(comp);
        if (it == node->children.end())
            return nullptr;
        node = it->second;
    }
    return node;
}

// Returns parent node and sets 'child' to the last component
std::shared_ptr<MemNode> memfs_parent(const std::string& path, std::string& child) {
    auto comps = split_path(path);
    if (comps.empty()) return nullptr;
    child = comps.back();
    comps.pop_back();
    auto node = root;
    for (const auto& comp : comps) {
        auto it = node->children.find(comp);
        if (it == node->children.end() || it->second->type != MemNodeType::Directory)
            return nullptr;
        node = it->second;
    }
    return node;
}