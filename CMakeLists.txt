cmake_minimum_required(VERSION 3.5)
project (pcap_cpp VERSION 1.0.0 LANGUAGES CXX)

#find_package(PCAP REQUIRED)

set(CMAKE_CXX_STANDARD 17)

include_directories(pcap_cpp)

add_subdirectory(examples)
