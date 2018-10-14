#ifndef __CAP_NG_PCAP_FILE_WRITER_DEVICE__
#define __CAP_NG_PCAP_FILE_WRITER_DEVICE__

#include "cap.noncopyable.h"
#include "cap.file_device.h"

#include "light_pcapng_ext.h"

namespace cap
{
	class pcap_ng_file_writer_device : public file_writer_device,
		private noncopyable
	{
		::light_pcapng_t* pcap_;
	public:
		pcap_ng_file_writer_device(const char* name);
		virtual ~pcap_ng_file_writer_device();
	public:
		bool open(int mode = 0);
		bool write_packet(const std::shared_ptr<packet>& pkt);
		bool write_packets(const std::vector<std::shared_ptr<packet>>& pkts);
		void close(void);
	private:
		static std::uint16_t linktype(const cap::linktype_t& lt);
	};
}

#endif

