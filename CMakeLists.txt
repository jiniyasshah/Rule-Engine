cmake_minimum_required(VERSION 3.10)

project(CppSocketServer)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)

# Add source directory
include_directories(src)
include_directories(headers)  # Add headers directory

# Add JsonCpp include directory (adjust the path if using vcpkg or manual installation)
include_directories("C:/vcpkg/installed/x64-windows/include")

# Define _CRT_SECURE_NO_WARNINGS to avoid deprecation warnings
add_definitions(-D_CRT_SECURE_NO_WARNINGS)

# Add the executable
add_executable(CppSocketServer 
    main.cpp 
    codebase/rule_engine.cpp 
    codebase/http_handler.cpp 
    codebase/network_uploader.cpp
    codebase/dos.cpp)

# Link required Windows libraries
target_link_libraries(CppSocketServer Ws2_32)
target_link_libraries(CppSocketServer WinHTTP)  # Add WinHTTP lib

# Enable multi-threading support if available
find_package(Threads QUIET)
if(Threads_FOUND)
    target_link_libraries(CppSocketServer Threads::Threads)
endif()