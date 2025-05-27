#include "memfs.h"
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <json/json.h>

MemFS memfs;

MemFSNode::MemFSNode(const std::string& n, NodeType t, mode_t m, uid_t u, gid_t g, std::weak_ptr<MemFSNode> p)
    : name(n), type(t), mode(m), uid(u), gid(g), parent(p) {
    time(&atime);
    mtime = atime;
    ctime = atime;
    size = 0;
}

static void node_to_json(const std::shared_ptr<MemFSNode>& node, Json::Value& jn) {
    jn["name"] = node->name;
    jn["type"] = (node->type == NodeType::File ? "file" : (node->type == NodeType::Directory ? "dir" : "symlink"));
    jn["data"] = node->data;
    jn["size"] = static_cast<Json::UInt64>(node->size);
    jn["mode"] = node->mode;
    jn["uid"] = node->uid;
    jn["gid"] = node->gid;
    jn["atime"] = static_cast<Json::Int64>(node->atime);
    jn["mtime"] = static_cast<Json::Int64>(node->mtime);
    jn["ctime"] = static_cast<Json::Int64>(node->ctime);
    if (node->type == NodeType::Directory) {
        for (auto& [n, child] : node->children) {
            Json::Value jc;
            node_to_json(child, jc);
            jn["children"].append(jc);
        }
    }
}

std::string MemFSNode::to_json() const {
    Json::Value jn;
    node_to_json(std::const_pointer_cast<MemFSNode>(shared_from_this()), jn);
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, jn);
}

static std::shared_ptr<MemFSNode> node_from_json(const Json::Value& jn, std::weak_ptr<MemFSNode> parent) {
    NodeType t = NodeType::File;
    std::string stype = jn["type"].asString();
    if (stype == "dir") t = NodeType::Directory;
    else if (stype == "symlink") t = NodeType::Symlink;
    auto node = std::make_shared<MemFSNode>(
        jn["name"].asString(), t, jn["mode"].asUInt(), jn["uid"].asUInt(), jn["gid"].asUInt(), parent
    );
    node->data = jn["data"].asString();
    node->size = jn["size"].asUInt64();
    node->atime = jn["atime"].asInt64();
    node->mtime = jn["mtime"].asInt64();
    node->ctime = jn["ctime"].asInt64();
    if (t == NodeType::Directory) {
        const Json::Value& jch = jn["children"];
        for (const auto& jc : jch) {
            auto child = node_from_json(jc, node);
            node->children[child->name] = child;
        }
    }
    return node;
}

std::shared_ptr<MemFSNode> MemFSNode::from_json(const std::string& json, std::weak_ptr<MemFSNode> parent) {
    Json::CharReaderBuilder b;
    Json::Value root;
    std::istringstream s(json);
    std::string errs;
    if (!Json::parseFromStream(b, s, &root, &errs)) return nullptr;
    return node_from_json(root, parent);
}

MemFS::MemFS() {
    root = std::make_shared<MemFSNode>("/", NodeType::Directory, 0755, getuid(), getgid(), std::weak_ptr<MemFSNode>());
    root->parent.reset();
}

void MemFS::save() {
    std::ofstream ofs(PERSISTENCE_FILE, std::ios::trunc);
    ofs << root->to_json();
}

void MemFS::load() {
    std::ifstream ifs(PERSISTENCE_FILE);
    if (!ifs) return;
    std::stringstream buf;
    buf << ifs.rdbuf();
    std::string content = buf.str();
    auto r = MemFSNode::from_json(content, std::weak_ptr<MemFSNode>());
    if (r) {
        root = r;
        root->parent.reset();
    }
}