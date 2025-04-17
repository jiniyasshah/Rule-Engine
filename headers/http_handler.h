#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include <string>
#include "rule_engine.h"
#include "dos.h"

class HttpHandler {
public:
    explicit HttpHandler(RuleEngine& ruleEngine);

    // Inspect the HTTP request and decide whether to allow or block it
    std::string inspectRequest(const std::string& httpRequest);
    
    // Set the DOS protection module (optional, can be done in constructor)
    void setDOSProtection(DOSProtection* dosProtection);

private:
    RuleEngine& ruleEngine; // Reference to the RuleEngine
    DOSProtection* dosProtection; // Pointer to the DOS protection module
    
    // Helper method to extract client IP from request
    std::string extractClientIP(const std::string& httpRequest);
};

#endif // HTTP_HANDLER_H