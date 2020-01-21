#include <iostream>
#include "pcap_cpp.h"

using namespace std::literals::string_view_literals;

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		std::cerr << "Usage: ./dup original.pcap backup.pcap\n";
		return 1;
	}

	pcap_parser parser;
	if (!parser.open(argv[1]))
	{
		std::cerr << parser.error() << '\n';
		return 1;
	}

	pcap_dumper dumper;
	if (!dumper.open(argv[2]))
	{
		std::cerr << dumper.error() << '\n';
		return 1;
	}

	pcap_packet packet;
	while (parser.get_next_packet(packet))
	{
		dumper.dump_packet(packet);
	}

	if (!parser.feof())
	{
		std::cerr << parser.error() << '\n';
		return 1;
	}

	std::cout << "The pcap file has " << parser.count() << " packets\n";
	return 0;
}
