#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>
#include <thread>
#include <vector>
#include <mutex>
#include "./headers/rule_engine.h"
#include "./headers/http_handler.h"

#pragma comment(lib, "Ws2_32.lib")

RuleEngine ruleEngine;
HttpHandler* httpHandler = nullptr;

SOCKET listenSocket = INVALID_SOCKET;
bool running = true;
std::mutex coutMutex;

void signalHandler(int signal) {
    std::lock_guard<std::mutex> lock(coutMutex);
    std::cout << "\nShutdown signal received, closing server..." << std::endl;
    running = false;
    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
    }
}

void initializeRuleEngine() {
    std::string rulesFilePath = "rules.txt";
    if (!ruleEngine.loadRules(rulesFilePath)) {
        std::cerr << "Failed to load rules. Exiting..." << std::endl;
        exit(1);
    }
    std::cout << "Rules loaded successfully!" << std::endl;
}

void initializeHttpHandler() {
    httpHandler = new HttpHandler(ruleEngine);
}

void initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "Winsock initialization failed with error: " << result << std::endl;
        exit(1);
    }
}

SOCKET setupListeningSocket(int port) {
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        exit(1);
    }

    u_long mode = 1;
    ioctlsocket(socket, FIONBIO, &mode);

    int enable = 1;
    setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(enable));

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(socket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR ||
        listen(socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Socket bind/listen failed: " << WSAGetLastError() << std::endl;
        closesocket(socket);
        WSACleanup();
        exit(1);
    }

    return socket;
}

std::string analyzeRequest(const std::string& data) {
    if (httpHandler != nullptr) {
        try {
            return httpHandler->inspectRequest(data);
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cerr << "Error in HttpHandler: " << e.what() << std::endl;
        }
    }
    return data.find("malicious") != std::string::npos ? "false" : "true";
}

void handleClient(SOCKET clientSocket) {
    char buffer[4096];
    int bytesReceived;
    int retryCount = 3;
    DWORD timeout = 5000;

    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cout << "Waiting to receive data from client..." << std::endl;
    }

    while (retryCount-- > 0) {
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::string requestData(buffer);

            {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "Received Data:\n" << requestData << std::endl;
            }

            std::string result = analyzeRequest(requestData);

            {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << (result == "false" ? "Request blocked." : "Request allowed.") << std::endl;
            }

            send(clientSocket, result.c_str(), result.length(), 0);
            break;
        } else if (bytesReceived == 0) {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "Client disconnected" << std::endl;
            break;
        } else {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK || error == WSAETIMEDOUT) {
                Sleep(100);
            } else {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cerr << "Receive error: " << error << std::endl;
                break;
            }
        }
    }

    closesocket(clientSocket);
}

int main() {
    int port = 12345;
    signal(SIGINT, signalHandler);

    initializeWinsock();
    initializeRuleEngine();
    initializeHttpHandler();
    listenSocket = setupListeningSocket(port);

    std::cout << "Server started on port " << port << ". Press Ctrl+C to stop." << std::endl;

    while (running) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);

        if (clientSocket != INVALID_SOCKET) {
            std::thread clientThread(handleClient, clientSocket);
            clientThread.detach(); // Let the thread run independently
        } else {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cerr << "Accept failed: " << error << std::endl;
            }
            Sleep(50); // Avoid tight loop
        }
    }

    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
    }
    WSACleanup();
    delete httpHandler;

    std::cout << "Server shut down successfully" << std::endl;
    return 0;
}
