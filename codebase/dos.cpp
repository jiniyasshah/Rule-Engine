#include "../headers/dos.h"

DOSProtection::DOSProtection(unsigned int requestThreshold, unsigned int timeWindowSeconds)
    : threshold(requestThreshold), timeWindowSeconds(timeWindowSeconds) {
}

bool DOSProtection::isAllowed(const std::string& clientIP) {
    std::lock_guard<std::mutex> lock(mapMutex);
    
    // First check if we need to reset the counter
    checkAndResetCounter(clientIP);
    
    // If IP doesn't exist yet, it's allowed
    if (ipMap.find(clientIP) == ipMap.end()) {
        return true;
    }
    
    // Check if request count is below threshold
    return ipMap[clientIP].requestCount < threshold;
}

void DOSProtection::registerRequest(const std::string& clientIP) {
    std::lock_guard<std::mutex> lock(mapMutex);
    
    // First check if we need to reset the counter
    checkAndResetCounter(clientIP);
    
    // If the IP doesn't exist in our map yet, add it
    if (ipMap.find(clientIP) == ipMap.end()) {
        ipMap[clientIP] = IPTracker();
    }
    
    // Increment the request count
    ipMap[clientIP].requestCount++;
    
    // Debug output - consider removing or using a proper logging system in production
    std::cout << "IP: " << clientIP << " - Request count: " << ipMap[clientIP].requestCount << std::endl;
}

void DOSProtection::checkAndResetCounter(const std::string& clientIP) {
    // Skip if the IP doesn't exist in our map yet
    if (ipMap.find(clientIP) == ipMap.end()) {
        return;
    }
    
    auto& tracker = ipMap[clientIP];
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - tracker.lastReset).count();
    
    // Reset counter if time window has passed
    if (elapsed >= timeWindowSeconds) {
        tracker.requestCount = 0;
        tracker.lastReset = now;
    }
}

void DOSProtection::setThreshold(unsigned int newThreshold) {
    std::lock_guard<std::mutex> lock(mapMutex);
    threshold = newThreshold;
}

void DOSProtection::setTimeWindow(unsigned int newTimeWindowSeconds) {
    std::lock_guard<std::mutex> lock(mapMutex);
    timeWindowSeconds = newTimeWindowSeconds;
}

unsigned int DOSProtection::getThreshold() const {
    return threshold;
}

unsigned int DOSProtection::getTimeWindowSeconds() const {
    return timeWindowSeconds;
}

unsigned int DOSProtection::getRequestCount(const std::string& clientIP) {
    std::lock_guard<std::mutex> lock(mapMutex);
    
    if (ipMap.find(clientIP) == ipMap.end()) {
        return 0;
    }
    
    checkAndResetCounter(clientIP);
    return ipMap[clientIP].requestCount;
}

void DOSProtection::clearAllTracking() {
    std::lock_guard<std::mutex> lock(mapMutex);
    ipMap.clear();
}