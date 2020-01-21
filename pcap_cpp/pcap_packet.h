#pragma once

#include <pcap/pcap.h>
#include <vector>

struct pcap_packet
{
	size_t index;
	struct pcap_pkthdr *header;
	const u_char *data;
};
