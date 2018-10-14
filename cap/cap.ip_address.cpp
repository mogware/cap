#include "cap.ip_address.h"
#include "cap.config.h"

#include <cstring>

cap::ip_address::ip_address(void)
	: is_valid_(false)
{
}

cap::ip_address::~ip_address(void)
{
}

std::shared_ptr<cap::ip_address> cap::ip_address::of(const char* addr)
{
	in_addr ip4addr;
	in6_addr ip6addr;
	if (::inet_pton(AF_INET, addr, &ip4addr) != 0)
		return std::make_shared<ipv4_address>(addr);
	if (::inet_pton(AF_INET6, addr, &ip6addr) != 0)
		return std::make_shared<ipv6_address>(addr);
	return nullptr;
}

bool cap::ip_address::is_valid(void) const
{
	return is_valid_;
}

cap::ipv4_address::ipv4_address(const std::uint32_t& addr)
	: ip_address()
	, address_(addr)
{
	is_valid_ = true;
}

cap::ipv4_address::ipv4_address(const char* addr)
	: ip_address()
{
	in_addr ip4addr;
	if (::inet_pton(AF_INET, addr, &ip4addr) == 0)
		return;
	address_ = ip4addr.s_addr;
	is_valid_ = true;
}

cap::address_type_t cap::ipv4_address::get_type(void) const
{
	return type_ipv4;
}

std::string cap::ipv4_address::to_string(void) const
{
	in_addr ip4addr;
	ip4addr.s_addr = address_;
	char str[INET_ADDRSTRLEN];
	const char* addr = ::inet_ntop(AF_INET, &ip4addr, str, sizeof(str));
	return (addr != nullptr) ? addr : "";
}

std::uint32_t cap::ipv4_address::to_int(void) const
{
	return address_;
}

bool cap::ipv4_address::equals(std::uint32_t addr) const
{
	return address_ == addr;
}

cap::ipv6_address::ipv6_address(const std::uint64_t& high, const std::uint64_t& low)
	: ip_address()
	, high_(high)
	, low_(low)
{
	is_valid_ = true;
}

cap::ipv6_address::ipv6_address(const std::uint8_t* addr)
	: ip_address()
{
	init(addr);
	is_valid_ = true;
}

cap::ipv6_address::ipv6_address(const char* addr)
{
	in6_addr ip6addr;
	if (::inet_pton(AF_INET6, addr, &ip6addr) == 0)
		return;
	init(ip6addr.s6_addr);
	is_valid_ = true;
}

cap::address_type_t cap::ipv6_address::get_type(void) const
{
	return type_ipv6;
}

std::string cap::ipv6_address::to_string(void) const
{
	in6_addr ip6addr;
	bytes(ip6addr.s6_addr, high_);
	bytes(ip6addr.s6_addr+8, low_);
	char str[INET6_ADDRSTRLEN];
	const char* addr = ::inet_ntop(AF_INET6, &ip6addr, str, sizeof(str));
	return (addr != nullptr) ? addr : "";
}

std::uint64_t cap::ipv6_address::to_int_low(void) const
{
	return low_;
}

std::uint64_t cap::ipv6_address::to_int_high(void) const
{
	return high_;
}

bool cap::ipv6_address::equals(const std::uint8_t* addr) const
{
	in6_addr ip6addr;
	bytes(ip6addr.s6_addr, high_);
	bytes(ip6addr.s6_addr + 8, low_);
	return std::memcmp(ip6addr.s6_addr, addr, sizeof(in6_addr)) == 0;
}

void cap::ipv6_address::init(const std::uint8_t* addr)
{
	std::uint64_t msb = 0;
	for (int i = 0; i < 8; i++)
		msb = (msb << 8) | (addr[i] & 0xff);
	std::uint64_t lsb = 0;
	for (int i = 8; i < 16; i++)
		lsb = (lsb << 8) | (addr[i] & 0xff);
	high_ = msb;
	low_ = lsb;
}

void cap::ipv6_address::bytes(std::uint8_t* dst, const std::uint64_t& src)
{
	dst[0] = (src >> 56) & 0xff;
	dst[1] = (src >> 48) & 0xff;
	dst[2] = (src >> 40) & 0xff;
	dst[3] = (src >> 32) & 0xff;
	dst[4] = (src >> 24) & 0xff;
	dst[5] = (src >> 16) & 0xff;
	dst[6] = (src >> 8) & 0xff;
	dst[7] = (src >> 0) & 0xff;
}