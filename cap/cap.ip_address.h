#ifndef __CAP_IP_ADDRESS__
#define __CAP_IP_ADDRESS__

#include "cap.noncopyable.h"

#include <memory>
#include <cstdint>
#include <string>

namespace cap
{
	typedef enum { type_ipv4, type_ipv6 } address_type_t;

	class ip_address : private noncopyable
	{
	protected:
		bool is_valid_;
	public:
		ip_address(void);
		virtual ~ip_address(void);
	public:
		static std::shared_ptr<ip_address> of(const char* addr);
	public:
		bool is_valid(void) const;
	public:
		virtual address_type_t get_type(void) const = 0;
	public:
		virtual std::string to_string(void) const = 0;
	};

	class ipv4_address : public ip_address
	{
		std::uint32_t address_;
	public:
		ipv4_address(const std::uint32_t& addr);
		ipv4_address(const char* addr);
	public:
		address_type_t get_type(void) const;
	public:
		std::string to_string(void) const;
	public:
		std::uint32_t to_int(void) const;
	public:
		bool equals(std::uint32_t addr) const;
	};

	class ipv6_address : public ip_address
	{
		std::uint64_t high_;
		std::uint64_t low_;
	public:
		ipv6_address(const std::uint64_t& high, const std::uint64_t& low);
		ipv6_address(const std::uint8_t* addr);
		ipv6_address(const char* addr);
	public:
		address_type_t get_type(void) const;
	public:
		std::string to_string(void) const;
	public:
		std::uint64_t to_int_low(void) const;
		std::uint64_t to_int_high(void) const;
	public:
		bool equals(const std::uint8_t* addr) const;
	private:
		void init(const std::uint8_t* addr);
	private:
		static void bytes(std::uint8_t* dst, const std::uint64_t& src);
	};
}
#endif
