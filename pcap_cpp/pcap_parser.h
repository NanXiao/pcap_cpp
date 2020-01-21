#pragma once

#include <pcap/pcap.h>
#include <string_view>

#include "pcap_handle.h"
#include "pcap_processor.h"

class pcap_parser : public pcap_processor
{
public:
	bool open(std::string_view file_name) noexcept
	{
		auto h = pcap_open_offline(file_name.data(), err_buf.data());
		if (h != NULL)
		{
			handle.set(h);
			return true;
		}
		else
		{
			return false;
		}
		
	}

	void close() noexcept
	{
		reset();
	}
};
