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

void server_thread(int thread_id, int listen_sockfd, int num_threads) {
    fd_set read_fds, master_fds;
    int max_fd = listen_sockfd;
    std::map<int, int> client_sockets; // socket -> thread assignment
    
    FD_ZERO(&master_fds);
    FD_SET(listen_sockfd, &master_fds);
    
    int connection_count = 0;
    
    while (true) {
        read_fds = master_fds;
        
        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
        if (activity < 0) {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cerr << "Select error in thread " << thread_id << std::endl;
            break;
        }
        
        // Check for new connections on listening socket
        if (FD_ISSET(listen_sockfd, &read_fds)) {
            int client_sockfd = accept_connection(listen_sockfd);
            if (client_sockfd >= 0) {
                // Assign connection to thread based on connection count
                int assigned_thread = connection_count % num_threads;
                if (assigned_thread == thread_id) {
                    // This connection is assigned to current thread
                    FD_SET(client_sockfd, &master_fds);
                    client_sockets[client_sockfd] = thread_id;
                    max_fd = std::max(max_fd, client_sockfd);
                } else {
                    // This connection is not for this thread, close it
                    close(client_sockfd);
                }
                connection_count++;
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