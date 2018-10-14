#include "cap.pcap_file_reader_device.h"

#include <cstring>

cap::pcap_file_reader_device::pcap_file_reader_device(const char* name)
	: file_reader_device(name)
	, pcap_(nullptr)
	, link_type_(cap::ethernet)
{
}

cap::pcap_file_reader_device::~pcap_file_reader_device()
{
	close();
}

bool cap::pcap_file_reader_device::open(int)
{
	if (pcap_ != nullptr)
		return false;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_ = ::pcap_open_offline(file_name_.c_str(), errbuf);
	if (pcap_ == NULL)
		return false;
	int datalink = ::pcap_datalink(pcap_);
	switch (datalink)
	{
	case DLT_NULL:
		link_type_ = cap::null; break;
	case DLT_EN10MB:
		link_type_ = cap::ethernet; break;
	case DLT_LINUX_SLL:
		link_type_ = cap::linux_ssl; break;
	case DLT_PPP:
		link_type_ = cap::ppp; break;
	case 12:
		link_type_ = cap::raw1; break;
	case 14:
		link_type_ = cap::raw2; break;
	case 101:
		link_type_ = cap::raw; break;
	default:
		link_type_ = cap::ethernet; break;
	}
	is_closed_ = false;
	return true;
}

bool cap::pcap_file_reader_device::set_filter(const std::string& filt)
{
	if (is_closed_)
		return false;
	bpf_program prog;
	if (::pcap_compile(pcap_, &prog, filt.c_str(), 1, 0) < 0)
		return false;
	if (::pcap_setfilter(pcap_, &prog) < 0)
		return false;
	return true;
}

std::shared_ptr<cap::packet> cap::pcap_file_reader_device::get_next_packet() const
{
	pcap_pkthdr pkthdr;
	const uint8_t* pktdata = ::pcap_next(pcap_, &pkthdr);
	if (pktdata == nullptr)
		return nullptr;
	const_cast<pcap_file_reader_device*>(this)->packets_read_++;
	std::uint8_t* data = new uint8_t[pkthdr.caplen];
	std::memcpy(data, pktdata, pkthdr.caplen);
	return packet::of(data, pkthdr.caplen, pkthdr.ts, link_type_, pkthdr.len);
}

void cap::pcap_file_reader_device::close(void)
{
	if (pcap_ == nullptr)
		return;
	::pcap_close(pcap_);
	pcap_ = nullptr;
	is_closed_ = true;
}


