#include "cap.live_device.h"
#include "cap.pcap_live_device_list.h"

cap::live_device::~live_device(void)
{
}

bool cap::live_device::set_filter(const std::shared_ptr<cap::filter>& filt)
{
	return set_filter(filt->parse());
}

void cap::live_device::clear_filter(void)
{
	set_filter("");
}

cap::live_device_list::~live_device_list(void)
{
}

std::shared_ptr<cap::live_device_list> cap::live_device_list::create(void)
{
	return std::make_shared<pcap_live_device_list>();
}

std::shared_ptr<cap::live_device> cap::live_device_list::default_device(void)
{
	std::shared_ptr<live_device_list> list = create();
	if (list == nullptr)
		return nullptr;
	std::shared_ptr<live_device> device = list->lookup();
	if (device == nullptr)
		return nullptr;
	return device;
}