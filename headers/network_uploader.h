#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <memory>
#include <vector>

class NetworkUploader {
public:
    // Singleton instance getter
    static NetworkUploader& getInstance();

    // Initialize the uploader
    bool initialize(const std::wstring& userAgent = L"NIDS-PacketUploader/1.0");
    
    // Configuration
    void setServerDetails(const std::wstring& host, uint16_t port, const std::wstring& path);

    // Upload JSON data
    bool uploadPacketData(const std::string& jsonData);

    // Cleanup resources
    void cleanup();

    // Destructor
    ~NetworkUploader();

private:
    // Private constructor for singleton
    NetworkUploader();
    
    // Prevent copying
    NetworkUploader(const NetworkUploader&) = delete;
    NetworkUploader& operator=(const NetworkUploader&) = delete;

    // Internal helper methods
    bool sendRequest(const std::string& jsonData);
    std::string readResponse();

    // WinHTTP handles
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;

    // Server configuration
    std::wstring serverHost;
    uint16_t serverPort;
    std::wstring serverPath;
};