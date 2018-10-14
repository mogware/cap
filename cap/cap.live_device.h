#ifndef __CAP_LIVE_DEVICE__
#define __CAP_LIVE_DEVICE__

#include <memory>
#include <functional>

#include "cap.device.h"
#include "cap.filter.h"
#include "cap.packet.h"

namespace cap
{
	enum { promisc = 1, monitor = 2, immediate = 4, statistics = 8 };

	struct live_device : public device
	{
		virtual ~live_device();
		virtual const char* get_name(void) const = 0;
		virtual const char* get_desc(void) const = 0;
		virtual bool get_loopback(void) const = 0;
		virtual bool set_filter(const std::string& filt) = 0;
		bool set_filter(const std::shared_ptr<filter>& filt);
		void clear_filter(void);
		virtual void add_callback(
			const std::function<bool(const std::shared_ptr<packet>&)>& cb) = 0;
		virtual bool start(void) = 0;
		virtual void stop(void) = 0;
		virtual void run(void) = 0;
		virtual void wakeup(void) = 0;
		virtual void wait(void) = 0;
	};

	struct live_device_list
	{
		virtual ~live_device_list();
		virtual std::shared_ptr<live_device> lookup(void) const = 0;
		virtual std::shared_ptr<live_device>
			get_by_ip(const char* addr) const = 0;
		virtual std::shared_ptr<live_device>
			get_by_name(const char* name) const = 0;
		static std::shared_ptr<live_device_list> create(void);
		static std::shared_ptr<live_device> default_device(void);
	};
}

#endif
