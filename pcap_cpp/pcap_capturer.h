#pragma once

#include <pcap/pcap.h>
#include <memory>
#include <string_view>

#include "pcap_handle.h"
#include "pcap_processor.h"

class pcap_capturer : public pcap_processor
{
private:
	std::unique_ptr<pcap_if_t, void(*)(pcap_if_t *)> dev_list{
		nullptr,
		[](auto v)
		{
			if (v != nullptr)
			{
				pcap_freealldevs(v);
			}
		}
	};
	std::string device;
public:
	bool open(std::string_view dev_name = "", int promisc = 0, int timeout = 1000) noexcept
	{
		if (dev_name == "")
		{
			pcap_if_t *devs;
			if (pcap_findalldevs(&devs, err_buf.data()) == -1)
			{
				return false;
			}

			if (devs == nullptr)
			{
				format_error("No interfaces available for capture");
				return false;
			}
			
			dev_list.reset(devs);
			dev_name = devs->name;
		}
		
		auto h = pcap_open_live(dev_name.data(), snap_len, promisc, timeout, err_buf.data());
		if (h == nullptr)
		{
			return false;
		}
		else
		{
			device = dev_name;
			handle.set(h);
			return true;
		}
	}

	bool set_filter(std::string_view filter)
	{
		bpf_u_int32 localnet;
		bpf_u_int32 netmask;
		struct bpf_program filter_code;
		auto h = handle.get();
	
		if (pcap_lookupnet(device.c_str(), &localnet, &netmask, err_buf.data()) < 0)
		{
			localnet = 0;
			netmask = 0;
		}

		if ((pcap_compile(h, &filter_code, filter.data(), 1, netmask) < 0) ||
		    (pcap_setfilter(h, &filter_code) < 0))
		{
			pcap_freecode(&filter_code);
			format_error(pcap_geterr(h));
			return false;
		}
		
		pcap_freecode(&filter_code);
		return true;
	}

	void close() noexcept
	{
		reset();
	}
};
