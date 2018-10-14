#if defined(CAP_USE_LIGHT_PCAP_NG)
#include "cap.pcap_ng_file_reader_device.h"

#include <cstring>

cap::pcap_ng_file_reader_device::pcap_ng_file_reader_device(const char* name)
	: file_reader_device(name)
	, pcap_(nullptr)
	, bpf_initialized_(false)
	, bpf_linktype_(-1)
	, filter_("")
{
}

cap::pcap_ng_file_reader_device::~pcap_ng_file_reader_device()
{
	close();
}

bool cap::pcap_ng_file_reader_device::open(int)
{
	if (pcap_ != nullptr)
		return false;
	pcap_ = ::light_pcapng_open_read(file_name_.c_str(), LIGHT_FALSE);
	if (pcap_ == nullptr)
		return false;
	is_closed_ = false;
	return true;
}

bool cap::pcap_ng_file_reader_device::set_filter(const std::string& filt)
{
	bpf_program prog;
	if (pcap_compile_nopcap(9000, 1, &prog, filt.c_str(), 1, 0) < 0)
		return false;
	pcap_freecode(&prog);
	filter_ = filt;
	bpf_linktype_ = -1;
	return true;
}

std::shared_ptr<cap::packet> cap::pcap_ng_file_reader_device::get_next_packet() const
{
	light_packet_header pkthdr;
	const uint8_t* pktdata;
	if (!::light_get_next_packet(pcap_, &pkthdr, &pktdata))
		return nullptr;
	while (!match(pktdata, pkthdr.captured_length, pkthdr.timestamp, pkthdr.data_link))
	{
		if (!::light_get_next_packet(pcap_, &pkthdr, &pktdata))
			return nullptr;
	}
	const_cast<pcap_ng_file_reader_device*>(this)->packets_read_++;
	std::uint8_t* data = new uint8_t[pkthdr.captured_length];
	std::memcpy(data, pktdata, pkthdr.captured_length);
	return packet::of(data, pkthdr.captured_length, pkthdr.timestamp,
		linktype(pkthdr.data_link), pkthdr.original_length);
}

void cap::pcap_ng_file_reader_device::close(void)
{
	if (pcap_ == nullptr)
		return;
	::light_pcapng_close(pcap_);
	pcap_ = nullptr;
	is_closed_ = true;
}

cap::linktype_t cap::pcap_ng_file_reader_device::linktype(const std::uint16_t& lt)
{
	switch (lt)
	{
	case DLT_NULL:
		return cap::null;
	case DLT_EN10MB:
		return cap::ethernet;
	case DLT_LINUX_SLL:
		return cap::linux_ssl;
	case DLT_PPP:
		return cap::ppp;
	case 12:
		return cap::raw1;
	case 14:
		return cap::raw2;
	case 101:
		return cap::raw;
	default:
		return cap::ethernet;
	}
}

bool cap::pcap_ng_file_reader_device::match(const std::uint8_t* data,
	const std::uint32_t& dlen, const cap::timeval_t& ts,
	const std::uint16_t& lt) const
{
	if (filter_.empty())
		return true;
	int ltint = static_cast<int>(lt);
	pcap_ng_file_reader_device* p = const_cast<pcap_ng_file_reader_device*>(this);
	if (p->bpf_linktype_ != ltint)
	{
		if (p->bpf_initialized_)
			::pcap_freecode(&p->bpf_);
		if (::pcap_compile_nopcap(9000, ltint, &p->bpf_, filter_.c_str(), 1, 0) < 0)
		{
			p->bpf_initialized_ = false;
			return false;
		}

		p->bpf_linktype_ = ltint;
		p->bpf_initialized_ = true;
	}
	pcap_pkthdr pkthdr;
	pkthdr.caplen = dlen;
	pkthdr.len = dlen;
	pkthdr.ts = ts;
	return (::pcap_offline_filter(&p->bpf_, &pkthdr, data) != 0);
}

#endif /* CAP_USE_LIGHT_PCAP_NG */
