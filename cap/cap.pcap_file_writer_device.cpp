#include "cap.pcap_file_writer_device.h"

cap::pcap_file_writer_device::pcap_file_writer_device(
	const char* name, linktype_t lt)
	: file_writer_device(name)
	, pcap_(nullptr)
	, pcap_dumper_(nullptr)
	, link_type_(lt)
{
}

cap::pcap_file_writer_device::~pcap_file_writer_device()
{
	close();
}

bool cap::pcap_file_writer_device::open(int)
{
	if (pcap_ != nullptr)
		return false;
	int datalink;
	switch (link_type_)
	{
	case cap::null:
		datalink = DLT_NULL; break;
	case cap::ethernet:
		datalink = DLT_EN10MB; break;
	case cap::linux_ssl:
		datalink = DLT_LINUX_SLL; break;
	case cap::raw1:
		datalink = 12; break;
	default:
		return false;
	}
	pcap_ = ::pcap_open_dead(datalink, 65536);
	if (pcap_ == nullptr)
		return false;
	pcap_dumper_ = ::pcap_dump_open(pcap_, file_name_.c_str());
	if (pcap_dumper_ == nullptr)
	{
		::pcap_close(pcap_);
		pcap_ = nullptr;
		return false;
	}

	is_closed_ = false;
	return true;
}

bool cap::pcap_file_writer_device::write_packet(
	const std::shared_ptr<packet>& pkt)
{
	if (pcap_dumper_ == nullptr || pcap_ == nullptr)
	{
		packets_not_written_++;
		return false;
	}
	if (pkt->get_link_type() != link_type_)
	{
		packets_not_written_++;
		return false;
	}
	pcap_pkthdr pkthdr;
	pkthdr.caplen = pkt->get_data_length();
	pkthdr.len = pkt->get_frame_length();
	pkthdr.ts = pkt->get_packet_timestamp();
	::pcap_dump(reinterpret_cast<std::uint8_t*>(pcap_dumper_),
		&pkthdr, pkt->get_raw_data());
	packets_written_++;
	return true;
}

bool cap::pcap_file_writer_device::write_packets(
	const std::vector<std::shared_ptr<packet>>& pkts)
{
	for (auto iter = pkts.cbegin(); iter != pkts.cend(); ++iter)
	{
		if (!write_packet(*iter))
			return false;
	}
	return true;
}

void cap::pcap_file_writer_device::close(void)
{
	if (pcap_dumper_ == nullptr || pcap_ == nullptr)
		return;
	::pcap_dump_flush(pcap_dumper_);
	::pcap_dump_close(pcap_dumper_);
	::pcap_close(pcap_);
	pcap_dumper_ = nullptr;
	pcap_ = nullptr;
	is_closed_ = true;
}
