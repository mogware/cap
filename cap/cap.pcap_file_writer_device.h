#ifndef __CAP_PCAP_FILE_WRITER_DEVICE__
#define __CAP_PCAP_FILE_WRITER_DEVICE__

#include "cap.noncopyable.h"
#include "cap.file_device.h"

#include <pcap.h>

namespace cap
{
	class pcap_file_writer_device : public file_writer_device,
		private noncopyable
	{
		::pcap_t* pcap_;
		::pcap_dumper_t* pcap_dumper_;
		linktype_t link_type_;
	public:
		pcap_file_writer_device(const char* name, linktype_t lt = cap::ethernet);
		virtual ~pcap_file_writer_device();
	public:
		bool open(int mode = 0);
		bool write_packet(const std::shared_ptr<packet>& pkt);
		bool write_packets(const std::vector<std::shared_ptr<packet>>& pkts);
		void close(void);
	};
}

#endif

