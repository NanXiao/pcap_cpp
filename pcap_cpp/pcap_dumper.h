#pragma once

#include <pcap/pcap.h>
#include <memory>
#include <string_view>

#include "pcap_handle.h"
#include "pcap_packet.h"
#include "pcap_processor.h"

class pcap_dumper : public pcap_processor
{
private:
	std::unique_ptr<pcap_dumper_t, void(*)(pcap_dumper_t *)> dumper{
		nullptr,
		[](auto v)
		{
			if (v != nullptr)
			{
				pcap_dump_close(v);
			}
		}
	};

public:
	bool open(std::string_view file_name, int link_type = DLT_EN10MB) noexcept
	{
		auto h = pcap_open_dead(link_type, snap_len);
		if (h != NULL)
		{
			handle.set(h);
		}
		else
		{
			format_error("No memory");
			return false;
		}

		auto d = pcap_dump_open(h, file_name.data());
		if (d != NULL)
		{
			dumper.reset(d);
			return true;
		}
		else
		{
			handle.close();
			format_error(pcap_geterr(handle.get()));
			return false;
		}	
	}

	void dump_packet(pcap_packet& packet) noexcept
	{
		pcap_dump((u_char *)dumper.get(), packet.header, packet.data);
	}

	void close() noexcept
	{
		dumper.reset(nullptr);
		reset();
	}
};
