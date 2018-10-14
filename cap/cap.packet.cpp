#include "cap.packet.h"

#include <cstring>

cap::packet::packet(void)
	: data_(nullptr)
	, datalen_(0)
	, framelen_(0)
	, timestamp_({0,0})
	, linktype_(cap::ethernet)
	, delete_data_(true)
{
}

cap::packet::packet(std::uint8_t* data, const std::uint32_t& datalen,
	const cap::timeval_t& ts, const bool& delete_data, const cap::linktype_t& lt)
	: data_(data)
	, datalen_(datalen)
	, framelen_(datalen)
	, timestamp_(ts)
	, linktype_(lt)
	, delete_data_(delete_data)
{
}

cap::packet::packet(const cap::packet& other)
{
	copy(other, true);
}

cap::packet::~packet(void)
{
	if (delete_data_ && data_ != nullptr)
		delete[] data_;
}

std::shared_ptr<cap::packet> cap::packet::of(std::uint8_t* data,
		const std::uint32_t& dlen, const cap::timeval_t& ts,
		const cap::linktype_t& lt, const std::uint32_t& flen)
{
	std::shared_ptr<packet> pkt = std::make_shared<packet>();
	pkt->set_raw_data(data, dlen, ts, lt, flen);
	return pkt;
}

std::shared_ptr<cap::packet> cap::packet::of(std::uint8_t* data,
		const std::uint32_t& dlen, const cap::timeval_t& ts,
		const bool& delete_data, const cap::linktype_t& lt)
{
	return std::make_shared<packet>(data, dlen, ts, delete_data, lt);
}

cap::packet& cap::packet::operator=(const cap::packet& other)
{
	if (data_ != NULL)
		delete[] data_;
	copy(other, true);
	return *this;
}

std::uint8_t* cap::packet::get_raw_data(void) const
{
	return data_;
}

bool cap::packet::set_raw_data(uint8_t* data, const std::uint32_t& dlen,
	const timeval_t& ts, linktype_t lt, const std::uint32_t& flen)
{
	framelen_ = (flen == -1) ? dlen : flen;
	if (delete_data_ && data_ != nullptr)
		delete[] data_;
	data_ = data;
	datalen_ = dlen;
	timestamp_ = ts;
	linktype_ = lt;
	return true;
}

cap::linktype_t cap::packet::get_link_type(void) const
{
	return linktype_;
}

int cap::packet::get_data_length(void) const
{
	return datalen_;
}

int cap::packet::get_frame_length(void) const
{
	return framelen_;
}

cap::timeval_t cap::packet::get_packet_timestamp(void) const
{
	return timestamp_;
}

void cap::packet::copy(const cap::packet& other, const bool& alloc)
{
	if (other.data_ == nullptr)
		return;
	timestamp_ = other.timestamp_;
	if (alloc)
	{
		delete_data_ = true;
		data_ = new uint8_t[other.datalen_];
		datalen_ = other.datalen_;
	}
	std::memcpy(data_, other.data_, other.datalen_);
	linktype_ = other.linktype_;
	framelen_ = other.framelen_;
}