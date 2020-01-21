# pcap_cpp

A header-file-only modern C++ encapsulation of [libpcap](https://github.com/the-tcpdump-group/libpcap). It contains 3 main classes:  

a) [pcap_capturer](pcap_cpp/pcap_capturer.h): live capturing;  
b) [pcap_parser](pcap_cpp/pcap_parser.h): parse pcap files;  
c) [pcap_dumper](pcap_cpp/pcap_dumper.h): dump pcap files.  

## Usage

Just add [pcap_cpp](pcap_cpp) folder into the header file search path, and include [pcap_cpp.h](pcap_cpp/pcap_cpp.h). E.g.:  

```
#include "pcap_cpp/pcap_cpp.h"
```
