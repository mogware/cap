#include "cap.file_device.h"
#include "cap.pcap_file_reader_device.h"
#include "cap.pcap_file_writer_device.h"

#if defined(CAP_USE_LIGHT_PCAP_NG)
#include "cap.pcap_ng_file_reader_device.h"
#include "cap.pcap_ng_file_writer_device.h"
#endif

#include <fstream>

cap::file_device::file_device(const char* name)
	: file_name_(name)
{
}

cap::file_device::~file_device(void)
{
}

std::string cap::file_device::get_file_name(void)
{
	return file_name_;
}

cap::file_reader_device::file_reader_device(const char* name)
	: file_device(name)
	, packets_read_(0)
{
}

cap::file_reader_device::~file_reader_device(void)
{
}

std::shared_ptr<cap::file_reader_device> cap::file_reader_device::of(const char* name)
{
#if defined(CAP_USE_LIGHT_PCAP_NG)
	std::string filename = std::string(name);
	int pos = filename.find_last_of(".");
	std::string ext = pos == std::string::npos ? "" : filename.substr(pos);
	if (ext == ".pcapng")
		return std::make_shared<pcap_ng_file_reader_device>(name);
#endif
	return std::make_shared<pcap_file_reader_device>(name);
}

std::uint64_t cap::file_reader_device::get_size(void) const
{
	std::ifstream fs(file_name_, std::ifstream::ate | std::ifstream::binary);
	return fs.tellg();
}

bool cap::file_reader_device::get_statistics(stats& st) const
{
	st.recv = packets_read_;
	st.drop = 0;
	st.ifdrop = 0;
	return true;
}

bool cap::file_reader_device::set_filter(const std::shared_ptr<cap::filter>& filt)
{
	return set_filter(filt->parse());
}

void cap::file_reader_device::clear_filter(void)
{
	set_filter("");
}

int cap::file_reader_device::get_next_packets(std::vector<std::shared_ptr<packet>>& pkts, int count) const
{
	int nread = 0;
	while (true)
	{
		std::shared_ptr<packet> pkt = get_next_packet();
		if (pkt == nullptr)
			break;
		pkts.push_back(pkt);
		nread++;
		if (count > 0 && nread >= count)
			break;
	}
	return nread;
}

cap::file_writer_device::file_writer_device(const char* name)
	: file_device(name)
	, packets_written_(0)
	, packets_not_written_(0)
{
}

cap::file_writer_device::~file_writer_device(void)
{
}

std::shared_ptr<cap::file_writer_device> cap::file_writer_device::of(const char* name)
{
#if defined(CAP_USE_LIGHT_PCAP_NG)
	std::string filename = std::string(name);
	int pos = filename.find_last_of(".");
	std::string ext = pos == std::string::npos ? "" : filename.substr(pos);
	if (ext == ".pcapng")
		return std::make_shared<pcap_ng_file_writer_device>(name);
#endif
	return std::make_shared<pcap_file_writer_device>(name);
}

bool cap::file_writer_device::get_statistics(stats& st) const
{
	st.recv = packets_written_;
	st.drop = packets_not_written_;
	st.ifdrop = 0;
	return true;
}
