#if defined(CAP_USE_LIGHT_PCAP_NG)
#include "cap.pcap_ng_file_writer_device.h"

#include <pcap.h>

cap::pcap_ng_file_writer_device::pcap_ng_file_writer_device(const char* name)
	: file_writer_device(name)
	, pcap_(nullptr)
{
}

cap::pcap_ng_file_writer_device::~pcap_ng_file_writer_device()
{
	close();
}

bool cap::pcap_ng_file_writer_device::open(int)
{
	if (pcap_ != nullptr)
		return false;
	::light_pcapng_file_info* info = light_create_default_file_info();
	pcap_ = ::light_pcapng_open_write(file_name_.c_str(), info);
	if (pcap_ == nullptr)
		return false;
	is_closed_ = false;
	return true;

}

bool cap::pcap_ng_file_writer_device::write_packet(
	const std::shared_ptr<packet>& pkt)
{
	if (pcap_ == nullptr)
	{
		packets_not_written_++;
		return false;
	}
	light_packet_header pkthdr;
	pkthdr.captured_length = pkt->get_data_length();
	pkthdr.original_length = pkt->get_frame_length();
	pkthdr.timestamp = pkt->get_packet_timestamp();
	pkthdr.data_link = linktype(pkt->get_link_type());
	pkthdr.interface_id = 0;
	pkthdr.comment = nullptr;
	pkthdr.comment_length = 0;
	::light_write_packet(pcap_, &pkthdr, pkt->get_raw_data());
	packets_written_++;
	return true;
}

bool cap::pcap_ng_file_writer_device::write_packets(
	const std::vector<std::shared_ptr<packet>>& pkts)
{
	for (auto iter = pkts.cbegin(); iter != pkts.cend(); ++iter)
	{
		if (!write_packet(*iter))
			return false;
	}
	return true;
}

void cap::pcap_ng_file_writer_device::close(void)
{
	if (pcap_ == nullptr)
		return;
	::light_pcapng_close(pcap_);
	pcap_ = nullptr;
	is_closed_ = true;
}

std::uint16_t cap::pcap_ng_file_writer_device::linktype(const cap::linktype_t& lt)
{
	switch (lt)
	{
	case cap::null:
		return DLT_NULL;
	case cap::ethernet:
		return DLT_EN10MB;
	case cap::linux_ssl:
		return DLT_LINUX_SLL;
	case cap::ppp:
		return DLT_PPP;
	case cap::raw1:
		return 12;
	case cap::raw2:
		return 14;
	case cap::raw:
		return 101;
	default:
		return DLT_EN10MB;
	}
}

#endif /* CAP_USE_LIGHT_PCAP_NG */