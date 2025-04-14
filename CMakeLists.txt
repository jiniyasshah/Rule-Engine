cmake_minimum_required(VERSION 3.10)

project(CppSocketServer)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)

# Add source directory
include_directories(src)
include_directories(headers)  # Add headers directory

# Add JsonCpp include directory (adjust the path if using vcpkg or manual installation)
include_directories("C:/vcpkg/installed/x64-windows/include")

# Add the executable
add_executable(CppSocketServer main.cpp codebase/rule_engine.cpp codebase/http_handler.cpp codebase/network_uploader.cpp)

# Link required Windows libraries
target_link_libraries(CppSocketServer Ws2_32)
target_link_libraries(CppSocketServer WinHTTP)  # Add WinHTTP lib

# Link JsonCpp library (adjust path if using vcpkg or manual installation)
