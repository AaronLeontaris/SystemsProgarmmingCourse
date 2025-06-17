#include "utils.h"
#include "message.pb.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

extern "C" {

int listening_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    // Set SO_REUSEADDR to allow easier testing
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sockfd);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    
    if (listen(sockfd, SOMAXCONN) < 0) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

int connect_socket(const char *hostname, const int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    std::string port_str = std::to_string(port);
    int status = getaddrinfo(hostname, port_str.c_str(), &hints, &result);
    if (status != 0) {
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, result->ai_addr, result->ai_addrlen) < 0) {
        close(sockfd);
        freeaddrinfo(result);
        return -1;
    }
    
    freeaddrinfo(result);
    return sockfd;
}

int accept_connection(int sockfd) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_sockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
    return client_sockfd;
}

// Helper function to receive exactly n bytes
static int recv_all(int sockfd, void *buffer, size_t size) {
    char *buf = (char*)buffer;
    size_t received = 0;
    
    while (received < size) {
        ssize_t result = recv(sockfd, buf + received, size - received, 0);
        if (result <= 0) {
            return 1; // Error or connection closed
        }
        received += result;
    }
    return 0;
}

// Helper function to send exactly n bytes
static int send_all(int sockfd, const void *buffer, size_t size) {
    const char *buf = (const char*)buffer;
    size_t sent = 0;
    
    while (sent < size) {
        ssize_t result = send(sockfd, buf + sent, size - sent, 0);
        if (result <= 0) {
            return 1; // Error
        }
        sent += result;
    }
    return 0;
}

int recv_msg(int sockfd, int32_t *operation_type, int64_t *argument) {
    // First, receive the message size (4 bytes)
    uint32_t msg_size;
    if (recv_all(sockfd, &msg_size, sizeof(msg_size)) != 0) {
        return 1;
    }
    
    // Convert from network byte order
    msg_size = ntohl(msg_size);
    
    // Allocate buffer for the protobuf message
    char *buffer = new char[msg_size];
    if (recv_all(sockfd, buffer, msg_size) != 0) {
        delete[] buffer;
        return 1;
    }
    
    // Parse the protobuf message
    sockets::message msg;
    if (!msg.ParseFromArray(buffer, msg_size)) {
        delete[] buffer;
        return 1;
    }
    
    delete[] buffer;
    
    // Extract values
    *operation_type = static_cast<int32_t>(msg.type());
    if (msg.has_argument()) {
        *argument = msg.argument();
    } else {
        *argument = 0;
    }
    
    return 0;
}

int send_msg(int sockfd, int32_t operation_type, int64_t argument) {
    // Create protobuf message
    sockets::message msg;
    msg.set_type(static_cast<sockets::message::OperationType>(operation_type));
    if (operation_type == OPERATION_ADD || operation_type == OPERATION_SUB || operation_type == OPERATION_COUNTER) {
        msg.set_argument(argument);
    }
    
    // Serialize the message
    std::string serialized;
    if (!msg.SerializeToString(&serialized)) {
        return 1;
    }
    
    // Send size first (4 bytes in network byte order)
    uint32_t msg_size = htonl(serialized.size());
    if (send_all(sockfd, &msg_size, sizeof(msg_size)) != 0) {
        return 1;
    }
    
    // Send the serialized message
    if (send_all(sockfd, serialized.data(), serialized.size()) != 0) {
        return 1;
    }
    
    return 0;
}

} // extern "C"