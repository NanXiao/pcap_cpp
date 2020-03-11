#include <iostream>
#include "pcap_cpp.h"

using namespace std::literals::string_view_literals;

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		std::cerr << "Usage: ./packet_len original.pcap\n";
		return 1;
	}

	pcap_parser parser;
	if (!parser.open(argv[1]))
	{
		std::cerr << parser.error() << '\n';
		return 1;
	}

	pcap_packet packet;
	while (parser.get_next_packet(packet))
	{
		std::cout << "Index " << packet.index << ": packet length is " << packet.header->caplen << '\n';
	}

	if (!parser.feof())
	{
		std::cerr << parser.error() << '\n';
		return 1;
	}

	std::cout << "The pcap file has " << parser.count() << " packets\n";
	return 0;
}
