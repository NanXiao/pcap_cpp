#pragma once

#include <array>
#include <pcap/pcap.h>
#include <string_view>

#include "pcap_handle.h"
#include "pcap_packet.h"

class pcap_processor
{
protected:
	std::array<char, PCAP_ERRBUF_SIZE> err_buf;
	pcap_handle handle;
	size_t index = 0;
	bool eof = false;
	int snap_len = 262144;

	void reset() noexcept
	{
		handle.close();
		index = 0;
		eof = false;
	}

	void format_error(std::string_view s)
	{
		snprintf(err_buf.data(), err_buf.size(), "%s", s.data());
	}
public:
	bool feof() const noexcept {
		return eof;
	}

	const std::string_view error() const noexcept {
		return err_buf.data();
	}

	const size_t count() const noexcept {
		return index;
	}

	bool get_next_packet(pcap_packet& packet) noexcept
	{
		if (int ret = pcap_next_ex(handle.get(), &packet.header, &packet.data); ret == 1) {
			packet.index = index++;
			return true;
		} 
		else if ((ret == 0) || (ret == PCAP_ERROR_BREAK))
		{
			eof = true;
			return false;
		}
		else
		{
			format_error(pcap_geterr(handle.get()));
			return false;
		}
	}
};
