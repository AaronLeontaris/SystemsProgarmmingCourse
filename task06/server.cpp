#include "utils.h"
#include "message.pb.h"
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#include <map>
#include <algorithm>

std::atomic<int64_t> global_counter{0};
std::mutex print_mutex;
std::mutex assign_mutex;
std::atomic<int> connection_count{0};

// Set socket to non-blocking mode
int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

void server_thread(int thread_id, int listen_sockfd, int num_threads) {
    fd_set read_fds, master_fds;
    int max_fd = listen_sockfd;
    std::map<int, bool> client_sockets; // socket -> managed by this thread
    
    FD_ZERO(&master_fds);
    FD_SET(listen_sockfd, &master_fds);
    
    struct timeval timeout;
    
    while (true) {
        read_fds = master_fds;
        
        // Set a short timeout to avoid blocking indefinitely
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms
        
        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        if (activity < 0) {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cerr << "Select error in thread " << thread_id << std::endl;
            continue; // Don't break, just try again
        }
        
        // Check for new connections on listening socket
        if (FD_ISSET(listen_sockfd, &read_fds)) {
            int client_sockfd = accept_connection(listen_sockfd);
            if (client_sockfd >= 0) {
                // Set socket to non-blocking mode
                if (set_nonblocking(client_sockfd) < 0) {
                    close(client_sockfd);
                    continue;
                }
                
                // Thread-safe connection count increment and assignment
                int conn_id;
                {
                    std::lock_guard<std::mutex> lock(assign_mutex);
                    conn_id = connection_count++;
                }
                
                // Assign connection to thread based on connection count
                int assigned_thread = conn_id % num_threads;
                
                if (assigned_thread == thread_id) {
                    // This connection is assigned to current thread
                    FD_SET(client_sockfd, &master_fds);
                    client_sockets[client_sockfd] = true;
                    max_fd = std::max(max_fd, client_sockfd);
                } else {
                    // This connection is not for this thread, close it
                    close(client_sockfd);
                }
            }
        }
        
        // Check for data on client sockets
        for (auto it = client_sockets.begin(); it != client_sockets.end();) {
            int client_sockfd = it->first;
            
            if (FD_ISSET(client_sockfd, &read_fds)) {
                int32_t operation_type;
                int64_t argument;
                
                int recv_result = recv_msg(client_sockfd, &operation_type, &argument);
                if (recv_result != 0) {
                    // Client disconnected or error
                    FD_CLR(client_sockfd, &master_fds);
                    close(client_sockfd);
                    it = client_sockets.erase(it);
                    continue;
                }
                
                switch (operation_type) {
                    case OPERATION_ADD:
                        global_counter.fetch_add(argument);
                        break;
                        
                    case OPERATION_SUB:
                        global_counter.fetch_sub(argument);
                        break;
                        
                    case OPERATION_TERMINATION: {
                        int64_t current_counter = global_counter.load();
                        
                        // Print counter value
                        {
                            std::lock_guard<std::mutex> lock(print_mutex);
                            std::cout << current_counter << std::endl;
                            std::cout.flush();
                        }
                        
                        // Send COUNTER response
                        if (send_msg(client_sockfd, OPERATION_COUNTER, current_counter) != 0) {
                            std::lock_guard<std::mutex> lock(print_mutex);
                            std::cerr << "Failed to send counter response" << std::endl;
                        }
                        
                        // Close connection after termination
                        FD_CLR(client_sockfd, &master_fds);
                        close(client_sockfd);
                        it = client_sockets.erase(it);
                        continue;
                    }
                        
                    default:
                        std::lock_guard<std::mutex> lock(print_mutex);
                        std::cerr << "Unknown operation type: " << operation_type << std::endl;
                        break;
                }
            }
            ++it;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <num_threads> <port>" << std::endl;
        return 1;
    }
    
    int num_threads = std::atoi(argv[1]);
    int port = std::atoi(argv[2]);
    
    // Create listening socket
    int listen_sockfd = listening_socket(port);
    if (listen_sockfd < 0) {
        std::cerr << "Failed to create listening socket" << std::endl;
        return 1;
    }
    
    // Set listening socket to non-blocking
    if (set_nonblocking(listen_sockfd) < 0) {
        std::cerr << "Failed to set listening socket to non-blocking mode" << std::endl;
        close(listen_sockfd);
        return 1;
    }
    
    std::vector<std::thread> threads;
    
    // Create server threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(server_thread, i, listen_sockfd, num_threads);
    }
    
    // Wait for threads (they run indefinitely)
    for (auto& thread : threads) {
        thread.join();
    }
    
    close(listen_sockfd);
    return 0;
}