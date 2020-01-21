add_executable(capturer capturer.cpp)
target_link_libraries(capturer pcap)

add_executable(dup dup.cpp)
target_link_libraries(dup pcap)
