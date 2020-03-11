add_executable(capturer capturer.cpp)
target_link_libraries(capturer pcap)

add_executable(dup dup.cpp)
target_link_libraries(dup pcap)

add_executable(packet_len packet_len.cpp)
target_link_libraries(packet_len pcap)
