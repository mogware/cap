#include "cap.config.h"
#include "cap.pcap_live_device_list.h"
#include "cap.pcap_live_device.h"

#include <pcap.h>
#if defined(CAP_WIN32)
#include <Packet32.h>
#endif

cap::pcap_live_device_list::pcap_live_device_list()
	: device_list_()
{
	pcap_if_t* list;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (::pcap_findalldevs(&list, errbuf) < 0)
		return;
	pcap_if_t* iface = list;
	while (iface != nullptr)
	{
		std::shared_ptr<live_device> dev =
			std::make_shared<pcap_live_device>(iface);
		device_list_.push_back(dev);
		iface = iface->next;
	}
	::pcap_freealldevs(list);
}

cap::pcap_live_device_list::~pcap_live_device_list()
{
}

std::shared_ptr<cap::live_device>
	cap::pcap_live_device_list::lookup(void) const
{
	if (device_list_.empty())
		return nullptr;
#if defined(CAP_WIN32)
	ULONG NameLength = 8192;
	static char AdaptersName[8192];
	if (PacketGetAdapterNames((PTSTR)AdaptersName, &NameLength))
	{
		std::shared_ptr<live_device> device = get_by_name(AdaptersName);
		if (device != nullptr)
			return device;
	}
#endif
	for (auto iter = device_list_.begin(); iter != device_list_.end(); ++iter)
	{
		if (!(*iter)->get_loopback())
			return *iter;
	}
	return nullptr;
}

std::shared_ptr<cap::live_device>
	cap::pcap_live_device_list::get_by_ip(const char* addr) const
{
	std::shared_ptr<ip_address> ipaddr = ip_address::of(addr);
	if (ipaddr == nullptr || !ipaddr->is_valid())
		return nullptr;
	if (ipaddr->get_type() == type_ipv4)
		return get_by_ipv4(static_cast<ipv4_address*>(ipaddr.get()));
	if (ipaddr->get_type() == type_ipv6)
		return get_by_ipv6(static_cast<ipv6_address*>(ipaddr.get()));
	return nullptr;
}

std::shared_ptr<cap::live_device>
	cap::pcap_live_device_list::get_by_name(const char* name) const
{
	for (auto iter = device_list_.begin(); iter != device_list_.end(); ++iter)
	{
		std::string devname((*iter)->get_name());
		if (devname.compare(name) == 0)
			return *iter;
	}
	return nullptr;
}

std::shared_ptr<cap::live_device>
	cap::pcap_live_device_list::get_by_ipv4(const ipv4_address* ip4addr) const
{
	for (auto d = device_list_.begin(); d != device_list_.end(); ++d)
	{
		pcap_live_device* dev = static_cast<pcap_live_device*>((*d).get());
		for (auto a = dev->addresses_.begin(); a != dev->addresses_.end(); ++a)
		{
			if ((*a).sa_family != AF_INET)
				continue;
			sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&(*a));
			if (ip4addr->equals(addr->sin_addr.s_addr))
				return *d;
		}
	}
	return nullptr;
}

std::shared_ptr<cap::live_device>
	cap::pcap_live_device_list::get_by_ipv6(const ipv6_address* ip6addr) const
{
	for (auto d = device_list_.begin(); d != device_list_.end(); ++d)
	{
		pcap_live_device* dev = static_cast<pcap_live_device*>((*d).get());
		for (auto a = dev->addresses_.begin(); a != dev->addresses_.end(); ++a)
		{
			if ((*a).sa_family != AF_INET6)
				continue;
			sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(&(*a));
			if (ip6addr->equals(addr->sin6_addr.s6_addr))
				return *d;
		}
	}
	return nullptr;
}