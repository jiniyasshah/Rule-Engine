#include "../headers/http_handler.h"
#include "../headers/network_uploader.h"
#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>

HttpHandler::HttpHandler(RuleEngine& ruleEngine) : ruleEngine(ruleEngine) {}

// Simple JSON parsing without external libraries
std::string getJsonValue(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) {
        return "";
    }
    
    // Find colon after key
    pos = json.find(":", pos + searchKey.length());
    if (pos == std::string::npos) {
        return "";
    }
    
    // Skip whitespace
    pos++;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }
    
    // Check if value is a string
    if (json[pos] == '"') {
        size_t endPos = json.find("\"", pos + 1);
        while (endPos != std::string::npos && json[endPos-1] == '\\') {
            endPos = json.find("\"", endPos + 1);
        }
        
        if (endPos != std::string::npos) {
            return json.substr(pos + 1, endPos - pos - 1);
        }
    }
    
    // For non-string values
    size_t endPos = json.find_first_of(",}", pos);
    if (endPos != std::string::npos) {
        return json.substr(pos, endPos - pos);
    }
    
    return "";
}

std::string HttpHandler::inspectRequest(const std::string& httpRequest) {
    try {
        // Simple parsing of JSON without using JsonCpp
        std::string url = getJsonValue(httpRequest, "url");
        std::string method = getJsonValue(httpRequest, "method");
        std::string body = getJsonValue(httpRequest, "body");
        
        // Build request data for rule matching
        std::string requestData = method + " " + url + "\n" + body;
        
        std::cout << "Inspecting request: " << url << std::endl;
        
        // Match the request data against the rules
        std::string matchResult = ruleEngine.match(requestData);

        if (!matchResult.empty()) {
            auto& uploader = NetworkUploader::getInstance();
            
            // Create an enhanced JSON that includes the match result
            std::ostringstream enhancedJson;
            enhancedJson << "{";
            
            // Add original request data, removing the outer braces
            std::string requestJson = httpRequest;
            if (!requestJson.empty() && requestJson.front() == '{' && requestJson.back() == '}') {
                requestJson = requestJson.substr(1, requestJson.length() - 2);
            }
            
            enhancedJson << requestJson;
            
            // Add comma if needed
            if (!requestJson.empty() && !requestJson.empty() && requestJson.back() != ',') {
                enhancedJson << ",";
            }
            
            // Add the match result
            enhancedJson << "\"match_result\":\"" << matchResult << "\"}";
            
            // Upload the enhanced JSON data
            if (!uploader.isInitialized() || !uploader.uploadPacketData(enhancedJson.str())) {
                // Handle error - maybe log it
                std::cerr << "Failed to upload packet data" << std::endl;
            }  

            std::cout << "Rule matched: " << matchResult << std::endl;
            return "false"; // Block the request if a rule matches
        }

        // Allow the request if no rule matches
        return "true";
    } catch (const std::exception& e) {
        std::cerr << "Exception while inspecting request: " << e.what() << std::endl;
        return "false"; // Block on exceptions
    }
}