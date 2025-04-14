#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include <string>
#include "rule_engine.h"

class HttpHandler {
public:
    explicit HttpHandler(RuleEngine& ruleEngine);

    // Inspect the HTTP request and decide whether to allow or block it
    std::string inspectRequest(const std::string& httpRequest);

private:
    RuleEngine& ruleEngine; // Reference to the RuleEngine
};

#endif // HTTP_HANDLER_H