#ifndef __CAP_PACKET__
#define __CAP_PACKET__

#include "cap.config.h"

#include <memory>
#include <cstdint>

namespace cap
{
	typedef enum { null, ethernet, linux_ssl, ppp, raw, raw1, raw2 } linktype_t;
	typedef struct ::timeval timeval_t;

	class packet
	{
		std::uint8_t* data_;
		std::uint32_t datalen_;
		std::uint32_t framelen_;
		timeval_t timestamp_;
		linktype_t linktype_;
		bool delete_data_;
	public:
		packet(void);
		packet(std::uint8_t* data, const std::uint32_t& datalen,
			const timeval_t& ts, const bool& delete_data,
			const linktype_t& lt = cap::ethernet);
		packet(const packet& other);
		virtual ~packet(void);
	public:
		static std::shared_ptr<packet> of(std::uint8_t* data,
			const std::uint32_t& dlen, const timeval_t& ts,
			const linktype_t& lt, const std::uint32_t& flen);
		static std::shared_ptr<packet> of(std::uint8_t* data,
			const std::uint32_t& dlen, const timeval_t& ts,
			const bool& delete_data, const linktype_t& lt);
	public:
		packet& operator=(const packet& other);
	public:
		std::uint8_t* get_raw_data(void) const;
		bool set_raw_data(uint8_t* data, const std::uint32_t& dlen,
			const timeval_t& ts, linktype_t lt = cap::ethernet,
			const std::uint32_t& flen = -1);
		linktype_t get_link_type(void) const;
		int get_data_length(void) const;
		int get_frame_length(void) const;
		timeval_t get_packet_timestamp(void) const;
	private:
		void copy(const packet& other, const bool& alloc = true);
	};
}

#endif