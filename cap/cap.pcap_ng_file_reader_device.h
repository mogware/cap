#ifndef __CAP_PCAP_NG_FILE_READER_DEVICE__
#define __CAP_PCAP_NG_FILE_READER_DEVICE__

#include "cap.noncopyable.h"
#include "cap.file_device.h"

#include <pcap.h>
#include "light_pcapng_ext.h"

namespace cap
{
	class pcap_ng_file_reader_device : public file_reader_device,
		private noncopyable
	{
		::light_pcapng_t* pcap_;
		struct bpf_program bpf_;
		bool bpf_initialized_;
		int bpf_linktype_;
		std::string filter_;
	public:
		pcap_ng_file_reader_device(const char* name);
		virtual ~pcap_ng_file_reader_device();
	public:
		bool open(int mode = 0);
		bool set_filter(const std::string& filt);
		std::shared_ptr<packet> get_next_packet() const;
		void close(void);
	private:
		static linktype_t linktype(const std::uint16_t& lt);
		bool match(const std::uint8_t* data, const std::uint32_t& dlen,
			const timeval_t& ts, const std::uint16_t& lt) const;
	};
}

#endif

