#include "utils.h"
#include "message.pb.h"
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <mutex>
#include <cstdlib>

std::mutex print_mutex;

void client_thread(const std::string& hostname, int port, int num_messages, int add_value, int sub_value) {
    // Connect to server
    int sockfd = connect_socket(hostname.c_str(), port);
    if (sockfd < 0) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cerr << "Failed to connect to server" << std::endl;
        return;
    }
    
    // Send messages alternating between ADD and SUB
    for (int i = 0; i < num_messages; i++) {
        int32_t operation_type;
        int64_t argument;
        
        if (i % 2 == 0) {
            // Even index: ADD
            operation_type = OPERATION_ADD;
            argument = add_value;
        } else {
            // Odd index: SUB
            operation_type = OPERATION_SUB;
            argument = sub_value;
        }
        
        if (send_msg(sockfd, operation_type, argument) != 0) {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cerr << "Failed to send message" << std::endl;
            close(sockfd);
            return;
        }
    }
    
    // Send TERMINATION message
    if (send_msg(sockfd, OPERATION_TERMINATION, 0) != 0) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cerr << "Failed to send termination message" << std::endl;
        close(sockfd);
        return;
    }
    
    // Receive COUNTER response
    int32_t response_type;
    int64_t counter_value;
    if (recv_msg(sockfd, &response_type, &counter_value) != 0) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cerr << "Failed to receive counter response" << std::endl;
        close(sockfd);
        return;
    }
    
    // Print the counter value
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << counter_value << std::endl;
        std::cout.flush();
    }
    
    close(sockfd);
}

int main(int argc, char* argv[]) {
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] << " <num_threads> <hostname> <port> <num_messages> <add> <sub>" << std::endl;
        return 1;
    }
    
    int num_threads = std::atoi(argv[1]);
    std::string hostname = argv[2];
    int port = std::atoi(argv[3]);
    int num_messages = std::atoi(argv[4]);
    int add_value = std::atoi(argv[5]);
    int sub_value = std::atoi(argv[6]);
    
    std::vector<std::thread> threads;
    
    // Create and start client threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(client_thread, hostname, port, num_messages, add_value, sub_value);
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    return 0;
}