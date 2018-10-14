#include "cap.mac_address.h"

#include <cstring>
#include <cstdlib>
#include <sstream>
#include <iomanip>

cap::mac_address::mac_address(const std::uint8_t* addr)
	: is_valid_(true)
{
	std::memcpy(address_, addr, 6);
}

cap::mac_address::mac_address(const char* addr)
{
	int i = 0;
	while (*addr != '\0' && i < 6)
	{
		std::uint8_t byte[3];
		std::memset(byte, 0, 3);
		byte[0] = *addr++;
		if (*addr == '\0')
			break;
		byte[1] = *addr++;
		if (*addr == ':')
			addr++;
		else if (*addr != '\0')
			break;
		address_[i++] = (std::uint8_t)
			std::strtol(reinterpret_cast<const char *>(byte), nullptr, 16);
	}
	is_valid_ = (i == 6);

}

cap::mac_address::~mac_address(void)
{
}

std::shared_ptr<cap::mac_address> cap::mac_address::of(const std::uint8_t* addr)
{
	return std::make_shared<mac_address>(addr);
}

std::shared_ptr<cap::mac_address> cap::mac_address::of(const char* addr)
{
	return std::make_shared<mac_address>(addr);
}

cap::mac_address::mac_address(const mac_address& other)
{
	std::memcpy(address_, other.address_, 6);
	is_valid_ = other.is_valid_;
}

cap::mac_address& cap::mac_address::operator=(const mac_address& other)
{
	std::memcpy(address_, other.address_, 6);
	is_valid_ = other.is_valid_;
	return *this;
}

bool cap::mac_address::operator==(const mac_address& other)
{
	for (int i = 0; i < 6; i++)
		if (address_[i] != other.address_[i])
			return false;
	return true;
}

bool cap::mac_address::operator!=(const mac_address& other)
{
	return !operator == (other);
}

bool cap::mac_address::is_valid(void) const
{
	return is_valid_;
}

std::string cap::mac_address::to_string(void) const
{
	std::ostringstream stream;
	stream << std::uppercase << std::setfill('0') << std::setw(2) <<
		std::hex << static_cast<int>(address_[0]);
	stream << ":" << static_cast<int>(address_[1]);
	stream << ":" << static_cast<int>(address_[2]);
	stream << ":" << static_cast<int>(address_[3]);
	stream << ":" << static_cast<int>(address_[4]);
	stream << ":" << static_cast<int>(address_[5]);
	return stream.str();
}