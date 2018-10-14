#ifndef __CAP_PCAP_LIVE_DEVICE_LIST__
#define __CAP_PCAP_LIVE_DEVICE_LIST__

#include <memory>
#include <vector>

#include "cap.noncopyable.h"
#include "cap.live_device.h"
#include "cap.ip_address.h"

namespace cap
{
	class pcap_live_device_list : public live_device_list,
		private noncopyable
	{
	private:
		std::vector<std::shared_ptr<live_device>> device_list_;
	public:
		pcap_live_device_list();
		virtual ~pcap_live_device_list();
	public:
		std::shared_ptr<live_device> lookup(void) const;
		std::shared_ptr<live_device> get_by_ip(const char* addr) const;
		std::shared_ptr<live_device> get_by_name(const char* name) const;
	private:
		std::shared_ptr<live_device>
			get_by_ipv4(const ipv4_address* ip4addr) const;
		std::shared_ptr<live_device>
			get_by_ipv6(const ipv6_address* ip6addr) const;
	};
}

#endif

