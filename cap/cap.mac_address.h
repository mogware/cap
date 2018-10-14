#ifndef __CAP_MAC_ADDRESS__
#define __CAP_MAC_ADDRESS__

#include <memory>
#include <cstdint>
#include <string>

namespace cap
{
	class mac_address
	{
		std::uint8_t address_[6];
		bool is_valid_;
	public:
		mac_address(const std::uint8_t* addr);
		mac_address(const char* addr);
		virtual ~mac_address(void);
	public:
		static std::shared_ptr<mac_address> of(const std::uint8_t* addr);
		static std::shared_ptr<mac_address> of(const char* addr);
	public:
		mac_address(const mac_address& other);
		mac_address& operator=(const mac_address& other);
	public:
		bool operator==(const mac_address& other);
		bool operator!=(const mac_address& other);
	public:
		bool is_valid(void) const;
	public:
		std::string to_string(void) const;
	};
}
#endif
