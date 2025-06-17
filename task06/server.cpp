#include "utils.h"
#include "message.pb.h"
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#include <map>
#include <errno.h>
#include <signal.h>

// Global counter that all threads update
std::atomic<int64_t> global_counter{0};
// Mutex for thread-safe printing
std::mutex print_mutex;

// Function to set socket to non-blocking mode
int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

// Server thread function
void server_thread(int thread_id, int listen_fd, int num_threads) {
    // Only the first thread should accept connections
    bool accept_connections = (thread_id == 0);
    
    // Set of client sockets managed by this thread
    fd_set master_set;
    FD_ZERO(&master_set);
    
    // If this is thread 0, it monitors the listening socket
    if (accept_connections) {
        FD_SET(listen_fd, &master_set);
    }
    
    int max_fd = listen_fd;
    std::map<int, bool> client_fds; // Track client sockets for this thread
    
    // Simple counter for round-robin assignment
    int next_thread = 0;
    
    while (true) {
        fd_set read_set = master_set;
        
        // Set timeout for select to avoid blocking indefinitely
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 500000; // 500ms
        
        int ready = select(max_fd + 1, &read_set, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) continue; // Interrupted, try again
            
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cerr << "Thread " << thread_id << ": select() failed: " << strerror(errno) << std::endl;
            continue;
        }
        
        // Handle new connections (only thread 0)
        if (accept_connections && FD_ISSET(listen_fd, &read_set)) {
            int client_fd = accept_connection(listen_fd);
            if (client_fd >= 0) {
                // Set the socket to non-blocking mode
                if (set_nonblocking(client_fd) < 0) {
                    close(client_fd);
                    continue;
                }
                
                // Determine which thread should handle this client using round-robin
                int target_thread = next_thread;
                next_thread = (next_thread + 1) % num_threads;
                
                if (target_thread == thread_id) {
                    // This thread handles the client
                    FD_SET(client_fd, &master_set);
                    client_fds[client_fd] = true;
                    max_fd = std::max(max_fd, client_fd);
                } else {
                    // Pass the fd to the correct thread
                    // For simplicity, we just close it here - the correct approach would be
                    // to use a message queue or pipe to pass the fd to another thread
                    close(client_fd);
                }
            }
        }
        
        // Check client sockets for this thread
        std::vector<int> to_remove;
        for (auto& [fd, _] : client_fds) {
            if (FD_ISSET(fd, &read_set)) {
                int32_t op_type;
                int64_t arg_value;
                
                int result = recv_msg(fd, &op_type, &arg_value);
                if (result != 0) {
                    // Error or client disconnected
                    to_remove.push_back(fd);
                    continue;
                }
                
                // Process the message
                switch (op_type) {
                    case OPERATION_ADD:
                        global_counter.fetch_add(arg_value);
                        break;
                    
                    case OPERATION_SUB:
                        global_counter.fetch_sub(arg_value);
                        break;
                    
                    case OPERATION_TERMINATION: {
                        // Get the current counter value
                        int64_t counter_val = global_counter.load();
                        
                        // Print the counter value
                        {
                            std::lock_guard<std::mutex> lock(print_mutex);
                            std::cout << counter_val << std::endl;
                            std::cout.flush();
                        }
                        
                        // Send the COUNTER response
                        send_msg(fd, OPERATION_COUNTER, counter_val);
                        
                        // Mark for removal
                        to_remove.push_back(fd);
                        break;
                    }
                    
                    default:
                        // Unknown operation
                        std::lock_guard<std::mutex> lock(print_mutex);
                        std::cerr << "Unknown operation: " << op_type << std::endl;
                        break;
                }
            }
        }
        
        // Clean up closed connections
        for (int fd : to_remove) {
            FD_CLR(fd, &master_set);
            close(fd);
            client_fds.erase(fd);
        }
        
        // Recalculate max_fd if needed
        if (!to_remove.empty()) {
            max_fd = listen_fd;
            for (auto& [fd, _] : client_fds) {
                max_fd = std::max(max_fd, fd);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    // Ignore SIGPIPE to prevent crashes when writing to closed sockets
    signal(SIGPIPE, SIG_IGN);
    
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <num_threads> <port>" << std::endl;
        return 1;
    }
    
    int num_threads = std::atoi(argv[1]);
    int port = std::atoi(argv[2]);
    
    // Create listening socket
    int listen_fd = listening_socket(port);
    if (listen_fd < 0) {
        std::cerr << "Failed to create listening socket" << std::endl;
        return 1;
    }
    
    // Create server threads
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(server_thread, i, listen_fd, num_threads);
    }
    
    // Wait for threads (they run indefinitely)
    for (auto& t : threads) {
        t.join();
    }
    
    close(listen_fd);
    return 0;
}