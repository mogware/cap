#ifndef __CAP_PCAP_LIVE_DEVICE__
#define __CAP_PCAP_LIVE_DEVICE__

#include <vector>
#include <thread>

#include "cap.noncopyable.h"
#include "cap.live_device.h"

#include <pcap.h>

namespace cap
{
	typedef struct sockaddr sockaddr_t;

	class pcap_live_device : public live_device, private noncopyable
	{
		::pcap_t* pcap_;
		std::string name_;
		std::string desc_;
		bool loopback_;
		linktype_t link_type_;
		std::vector<sockaddr_t> addresses_;
		volatile bool stop_thread_;
		std::thread capture_thread_;
		std::vector<std::function<bool(const std::shared_ptr<packet>&)>> callbacks_;
	public:
		pcap_live_device(::pcap_if_t* iface);
		virtual ~pcap_live_device();
	public:
		bool open(int mode = 0);
		void close(void);
	public:
		const char* get_name(void) const;
		const char* get_desc(void) const ;
		bool get_loopback(void) const;
	public:
		bool get_statistics(stats& st) const;
	public:
		bool set_filter(const std::string& filt);
	public:
		void add_callback(
			const std::function<bool(const std::shared_ptr<packet>&)>& cb);
	public:
		bool start(void);
		void stop(void);
	public:
		void run(void);
	public:
		void wakeup(void);
		void wait(void);
	private:
		static void capture_thread_proc(void* user);
		static void on_packet_arrives(std::uint8_t* user,
			const ::pcap_pkthdr* pkthdr, const std::uint8_t* pkt);
		friend class pcap_live_device_list;
	};
}

#endif
