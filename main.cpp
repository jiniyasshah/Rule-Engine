#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include "./headers/rule_engine.h"
#include "./headers/http_handler.h"
#include "./headers/network_uploader.h"
#include "headers/dos.h"
#pragma comment(lib, "Ws2_32.lib")

RuleEngine ruleEngine;
HttpHandler* httpHandler = nullptr;
SOCKET listenSocket = INVALID_SOCKET;
DOSProtection* dosProtection = nullptr;

std::atomic<bool> running(true);
std::mutex coutMutex;

// Thread pool variables
const int MAX_THREADS = 20;

std::vector<std::thread> threadPool;
std::mutex threadPoolMutex;
std::condition_variable threadPoolCondition;
std::queue<SOCKET> clientQueue;
std::atomic<int> activeThreads(0);

void signalHandler(int signal) {
    std::lock_guard<std::mutex> lock(coutMutex);
    std::cout << "\nShutdown signal received, closing server..." << std::endl;
    running = false;
    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
    }
    // Wake up all worker threads
    threadPoolCondition.notify_all();
}

bool initializeRuleEngine(const std::string& rulesFilePath) {
    std::cout << "Loading rules from " << rulesFilePath << std::endl;
    bool result = ruleEngine.loadRules(rulesFilePath);
    if (!result) {
        std::cerr << "Failed to load rules from " << rulesFilePath << std::endl;
        return false;
    }
    std::cout << "Rules loaded successfully!" << std::endl;
    return true;
}

void initializeHttpHandler() {
    httpHandler = new HttpHandler(ruleEngine);
}

bool initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "Winsock initialization failed with error: " << result << std::endl;
        return false;
    }
    std::cout << "Winsock initialized successfully" << std::endl;
    return true;
}

void initializeDOSProtection() {
    // Create a new DOS protection instance with threshold of 20 requests per 10 seconds
    dosProtection = new DOSProtection(20, 10);
    
    // Set DOS protection in the HTTP handler
    if (httpHandler != nullptr && dosProtection != nullptr) {
        httpHandler->setDOSProtection(dosProtection);
    }
}

SOCKET setupListeningSocket(int port) {
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return INVALID_SOCKET;
    }
    // Set socket to non-blocking mode
    u_long mode = 1;
    ioctlsocket(socket, FIONBIO, &mode);
    // Enable address reuse
    int enable = 1;
    setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(enable));
    // Set up the server address structure
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    // Bind and listen
    if (bind(socket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Socket bind failed: " << WSAGetLastError() << std::endl;
        closesocket(socket);
        return INVALID_SOCKET;
    }
    if (listen(socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Socket listen failed: " << WSAGetLastError() << std::endl;
        closesocket(socket);
        return INVALID_SOCKET;
    }
    std::cout << "Socket setup complete, listening on port " << port << std::endl;
    return socket;
}

std::string analyzeRequest(const std::string& data) {
    if (httpHandler != nullptr) {
        try {
            std::string result = httpHandler->inspectRequest(data);
            if (result == "false") {
                std::cout << "Request blocked: Potential malicious content detected" << std::endl;
            } else {
                std::cout << "Request allowed" << std::endl;
            }
            return result;
        } catch (const std::exception& e) {
            std::cerr << "Error in HttpHandler: " << e.what() << std::endl;
        }
    }
    // Fallback logic if httpHandler fails
    return data.find("malicious") != std::string::npos ? "false" : "true";
}

void handleClient(SOCKET clientSocket) {
    // Increment active thread count
    activeThreads++;
    char buffer[8192]; // Increased buffer size for larger requests
    int bytesReceived;
    int retryCount = 3;
    DWORD timeout = 5000; // 5 second timeout
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    std::cout << "Waiting to receive data from client (Socket: " << clientSocket << ")" << std::endl;
    while (retryCount-- > 0 && running) {
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::string requestData(buffer);
            std::cout << "Received " << bytesReceived << " bytes of data" << std::endl;
            std::string result = analyzeRequest(requestData);
            std::cout << (result == "false" ? "Blocked" : "Allowed") << " request. Sending response." << std::endl;
            send(clientSocket, result.c_str(), result.length(), 0);
            break;
        } else if (bytesReceived == 0) {
            std::cout << "Client disconnected" << std::endl;
            break;
        } else {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK || error == WSAETIMEDOUT) {
                Sleep(100);
            } else {
                std::cerr << "Receive error: " << error << std::endl;
                break;
            }
        }
    }
    closesocket(clientSocket);
    // Decrement active thread count
    activeThreads--;
}

// Thread pool worker function
void threadPoolWorker() {
    while (running) {
        SOCKET clientSocket = INVALID_SOCKET;
        {
            std::unique_lock<std::mutex> lock(threadPoolMutex);
            // Wait until there's a client to handle or the server is shutting down
            threadPoolCondition.wait(lock, [&]() {
                return !clientQueue.empty() || !running;
            });
            // If the server is shutting down and there are no more clients, exit
            if (!running && clientQueue.empty()) {
                break;
            }
            // Get the next client socket
            if (!clientQueue.empty()) {
                clientSocket = clientQueue.front();
                clientQueue.pop();
            }
        }
        // Process the client outside the lock
        if (clientSocket != INVALID_SOCKET) {
            handleClient(clientSocket);
        }
    }
}

int main(int argc, char* argv[]) {
    std::cout << "Starting NIDS Rule Engine" << std::endl;
    // Initialize signal handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    // Initialize Winsock
    if (!initializeWinsock()) {
        return 1;
    }
    // Initialize Rule Engine
    std::string rulesFile = "rules.txt";
    if (!initializeRuleEngine(rulesFile)) {
        return 1;
    }
    // Initialize HTTP Handler
    initializeHttpHandler();
    initializeDOSProtection();
    // Initialize NetworkUploader
    auto& uploader = NetworkUploader::getInstance();
    if (!uploader.initialize()) {
        std::cerr << "Failed to initialize network uploader" << std::endl;
        // Continue anyway, as this is not critical
    } else {
        // Fixed line below - removed parentheses after setServerDetails
        uploader.setServerDetails(L"nids-web.vercel.app", 443, L"/api/pusher");
        std::cout << "Network uploader initialized successfully" << std::endl;
    }
    // Get server port
    int port = 12345;

    // Setup listening socket
    listenSocket = setupListeningSocket(port);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Failed to set up listening socket" << std::endl;
        return 1;
    }
    std::cout << "Server started on port " << port << ". Press Ctrl+C to stop." << std::endl;
    // Initialize thread pool
    int numThreads = 4; // Default to 4 threads
    if (numThreads > MAX_THREADS) {
        numThreads = MAX_THREADS;
    }
    std::cout << "Starting thread pool with " << numThreads << " threads" << std::endl;
    for (int i = 0; i < numThreads; i++) {
        threadPool.emplace_back(threadPoolWorker);
    }
    // Main accept loop
    while (running) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket != INVALID_SOCKET) {
            std::cout << "Accepted new client connection" << std::endl;
            std::unique_lock<std::mutex> lock(threadPoolMutex);
            clientQueue.push(clientSocket);
            lock.unlock();
            // Notify one thread to wake up and process this client
            threadPoolCondition.notify_one();
        } else {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                std::cerr << "Accept failed: " << error << std::endl;
            }
            Sleep(50); // Avoid tight loop
        }
        // Log status periodically
        static int loopCounter = 0;
        if (++loopCounter % 100 == 0) {
            std::cout << "Active threads: " << activeThreads.load() << ", Queue size: " << clientQueue.size() << std::endl;
        }
    }
    // Cleanup before exit
    std::cout << "Shutting down server" << std::endl;
    // Notify all worker threads to exit
    {
        std::unique_lock<std::mutex> lock(threadPoolMutex);
        running = false;
        threadPoolCondition.notify_all();
    }
    // Join all threads
    for (auto& thread : threadPool) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    // Close remaining client connections
    while (!clientQueue.empty()) {
        SOCKET socket = clientQueue.front();
        clientQueue.pop();
        closesocket(socket);
    }
    // Final cleanup
    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
    }
    WSACleanup();
    delete httpHandler;
    delete dosProtection;
    std::cout << "Server shut down successfully" << std::endl;
    return 0;
}