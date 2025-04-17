#ifndef DOS_H
#define DOS_H

#include <string>
#include <map>
#include <chrono>
#include <mutex>
#include <iostream>

// Structure to track IP requests
struct IPTracker {
    unsigned int requestCount;
    std::chrono::time_point<std::chrono::steady_clock> lastReset;

    IPTracker() : requestCount(0), lastReset(std::chrono::steady_clock::now()) {}
};

class DOSProtection {
public:
    // Constructor - set default threshold and time window
    DOSProtection(unsigned int requestThreshold = 100, 
                  unsigned int timeWindowSeconds = 60);

    // Check if an IP has exceeded the threshold
    bool isAllowed(const std::string& clientIP);

    // Increment request count for an IP
    void registerRequest(const std::string& clientIP);

    // Change settings
    void setThreshold(unsigned int newThreshold);
    void setTimeWindow(unsigned int newTimeWindowSeconds);
    
    // Get current settings
    unsigned int getThreshold() const;
    unsigned int getTimeWindowSeconds() const;
    
    // Get current count for an IP (for monitoring/debugging)
    unsigned int getRequestCount(const std::string& clientIP);
    
    // Clear all tracking data
    void clearAllTracking();

private:
    std::map<std::string, IPTracker> ipMap;
    unsigned int threshold;
    unsigned int timeWindowSeconds;
    std::mutex mapMutex;  // For thread safety

    // Check if the time window has passed and reset counter if needed
    void checkAndResetCounter(const std::string& clientIP);
};

#endif // DOS_H