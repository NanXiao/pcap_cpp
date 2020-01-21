#pragma once

#include <pcap/pcap.h>
#include <utility>
#include <memory>

class pcap_handle
{
private:
	std::unique_ptr<pcap_t, void(*)(pcap_t *)> handle{
		nullptr,
		[](auto v)
		{
			if (v != nullptr)
			{
				pcap_close(v);
			}
		}
	};

public:
	void set(pcap_t *h) noexcept
	{
		handle.reset(h);
	}
	
	pcap_t *get() const noexcept
	{
		return handle.get();
	}

	void close() noexcept
	{
		handle.reset(nullptr);
	}
};
