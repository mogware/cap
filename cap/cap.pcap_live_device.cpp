#include "cap.config.h"
#include "cap.pcap_live_device.h"

cap::pcap_live_device::pcap_live_device(::pcap_if_t* iface)
	: live_device()
	, pcap_(nullptr)
	, name_("")
	, desc_("")
	, loopback_(false)
	, addresses_()
	, stop_thread_(false)
	, capture_thread_()
	, callbacks_()
{
	if (iface->name != nullptr)
		name_ = iface->name;
	if (iface->description != nullptr)
		desc_ = iface->description;
	loopback_ = (iface->flags & 0x1) == PCAP_IF_LOOPBACK;
	while (iface->addresses != NULL)
	{
		addresses_.push_back(*iface->addresses->addr);
		iface->addresses = iface->addresses->next;
	}
}

cap::pcap_live_device::~pcap_live_device()
{
}

bool cap::pcap_live_device::open(int mode)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_ = ::pcap_create(name_.c_str(), errbuf);
	if (pcap_ == nullptr)
		return false;
	::pcap_set_snaplen(pcap_, 9000);
	if ((mode & cap::promisc) != 0)
		::pcap_set_promisc(pcap_, 1);
#if defined(CAP_HAVE_MONITOR_MODE)
	if ((mode & cap::monitor) != 0)
		::pcap_set_rfmon(pcap_, 1);
#endif
#if defined(CAP_USE_OPEN_LIVE_TIMEOUT)
	::pcap_set_timeout(pcap_, 1);
#else
	::pcap_set_timeout(pcap_, -1);
#endif
#if defined(CAP_HAVE_IMMEDIATE_MODE)
	if ((mode & cap::immediate) != 0)
		::pcap_set_immediate_mode(pcap_, 1);
#endif
#if defined(CAP_WIN32)
	if ((mode & cap::statistics) != 0)
		::pcap_setmode(pcap_, 1);
#endif
	if (::pcap_activate(pcap_) != 0)
	{
		::pcap_close(pcap_);
		pcap_ = nullptr;
		return false;
	}
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

void cap::pcap_live_device::close(void)
{
	if (pcap_ == nullptr)
		return;
	::pcap_close(pcap_);
	pcap_ = nullptr;
	is_closed_ = true;
}

bool cap::pcap_live_device::get_statistics(stats& st) const
{
	::pcap_stat info;
	if (::pcap_stats(pcap_, &info) < 0)
		return false;
	st.recv = info.ps_recv;
	st.drop = info.ps_drop;
	st.ifdrop = info.ps_ifdrop;
	return true;
}

bool cap::pcap_live_device::set_filter(const std::string& filt)
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

const char* cap::pcap_live_device::get_name(void) const
{
	return name_.c_str();
}

const char* cap::pcap_live_device::get_desc(void) const
{
	return desc_.c_str();
}

bool cap::pcap_live_device::get_loopback(void) const
{
	return loopback_;
}

void cap::pcap_live_device::add_callback(
	const std::function<bool(const std::shared_ptr<cap::packet>&)>& cb)
{
	callbacks_.push_back(cb);
}

bool cap::pcap_live_device::start(void)
{
	try
	{
		capture_thread_ = std::thread(capture_thread_proc, this);
	}
	catch (const std::exception&)
	{
		return false;
	}
	return true;
}

void cap::pcap_live_device::stop(void)
{
	stop_thread_ = true;
	wakeup();
	wait();
	stop_thread_ = false;
}

void cap::pcap_live_device::run(void)
{
	stop_thread_ = false;
	while (!stop_thread_)
		::pcap_dispatch(pcap_, -1, on_packet_arrives,
			reinterpret_cast<std::uint8_t*>(this));
	stop_thread_ = false;
}

void cap::pcap_live_device::wakeup(void)
{
	::pcap_breakloop(pcap_);
}

void cap::pcap_live_device::wait(void)
{
	if (capture_thread_.joinable())
		capture_thread_.join();
}

void cap::pcap_live_device::on_packet_arrives(std::uint8_t* user,
	const ::pcap_pkthdr* pkthdr, const std::uint8_t* pkt)
{
	pcap_live_device* self = reinterpret_cast<pcap_live_device*>(user);
	std::shared_ptr<packet> p = packet::of(const_cast<std::uint8_t*>(pkt),
		pkthdr->caplen, pkthdr->ts, false, self->link_type_);
	for (const auto& cb : self->callbacks_)
		if (cb(p)) self->stop_thread_ = true;
}

void cap::pcap_live_device::capture_thread_proc(void* user)
{
	pcap_live_device* self = static_cast<pcap_live_device*>(user);
	while (!self->stop_thread_)
		::pcap_dispatch(self->pcap_, -1, on_packet_arrives,
			static_cast<std::uint8_t*>(user));
}