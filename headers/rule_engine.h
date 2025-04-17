#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <string>
#include <vector>
#include <regex>
#include <unordered_map>

struct Rule {
    // Header components
    std::string action;
    std::string protocol;
    std::string sourceIP;
    std::string sourcePort;
    std::string direction;
    std::string destIP;
    std::string destPort;
    
    // Options
    std::unordered_map<std::string, std::string> options;
    
    // Pattern matching
    std::string pattern;      // The raw pattern string
    std::regex regexPattern;  // Compiled regex pattern
    bool nocase = false;      // Case insensitivity flag
    bool isRegex = false;     // Flag to indicate if this is a regex rule or content rule
    std::string sid;          // Rule identifier (SID)
};

class RuleEngine {
public:
    // Load rules from a file
    bool loadRules(const std::string& filePath);
    
    // Match a packet against loaded rules
    std::string match(const std::string& packetData);
    
private:
    std::vector<Rule> rules;
    
    // Rule parsing methods
    Rule parseRule(const std::string& ruleString);
    void parseHeader(const std::string& header, Rule& rule);
    void parseOptions(const std::string& options, Rule& rule);
    std::pair<std::string, std::string> parseOption(const std::string& option);
    bool validateRule(const Rule& rule) const;
    std::string urlDecode(const std::string& str);
};

#endif // RULE_ENGINE_H