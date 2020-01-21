#include <iostream>
#include "pcap_cpp.h"

using namespace std::literals::string_view_literals;

int main()
{
	pcap_capturer capturer;

	if (!capturer.open())
	{
		std::cerr << capturer.error() << '\n';
		return 1;
	}

	if (!capturer.set_filter("tcp port 443"sv))
	{
		std::cerr << capturer.error() << '\n';
		return 1;
	}

	pcap_dumper dumper;
	if (!dumper.open("capture.pcap"sv))
	{
		std::cerr << dumper.error() << '\n';
		return 1;
	}

	pcap_packet packet;
	for (size_t i = 0; i < 10; i++)
	{
		if (capturer.get_next_packet(packet))
		{
			dumper.dump_packet(packet);
		}
		else if (capturer.feof())
		{
			std::cout << "Time out\n";
			break;
		}
		else
		{
			std::cerr << capturer.error() << '\n';
			return 1;
		}
	}

	return 0;
}
