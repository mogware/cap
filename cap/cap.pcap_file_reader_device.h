#ifndef __CAP_PCAP_FILE_READER_DEVICE__
#define __CAP_PCAP_FILE_READER_DEVICE__

#include "cap.noncopyable.h"
#include "cap.file_device.h"

#include <pcap.h>

namespace cap
{
	class pcap_file_reader_device : public file_reader_device,
		private noncopyable
	{
		::pcap_t* pcap_;
		linktype_t link_type_;
	public:
		pcap_file_reader_device(const char* name);
		virtual ~pcap_file_reader_device();
	public:
		bool open(int mode = 0);
		bool set_filter(const std::string& filt);
		std::shared_ptr<packet> get_next_packet() const;
		void close(void);
	};
}

#endif
