#include "cap.filter.h"
#include "cap.ip_address.h"

#include <sstream>

cap::filter::~filter(void)
{
}

cap::filter_with_direction::filter_with_direction(const cap::direction_t& dir)
{
	dir_ = dir;
}

std::string cap::filter_with_direction::parse_direction(void) const
{
	switch (dir_)
	{
	case dir_src:
		return "src";
	case dir_dst:
		return "dst";
	case dir_src_or_dst:
		return "src or dst";
	default:
		return "";
	}
}

cap::direction_t cap::filter_with_direction::get_direction(void) const
{
	return dir_;
}

cap::filter_with_operator::filter_with_operator(const cap::operator_t& oper)
{
	oper_ = oper;
}

std::string cap::filter_with_operator::parse_operator(void) const
{
	switch (oper_)
	{
	case op_eq:
		return "=";
	case op_ne:
		return "!=";
	case op_gt:
		return ">";
	case op_ge:
		return ">=";
	case op_lt:
		return "<";
	case op_le:
		return "<=";
	case op_and:
		return "and";
	case op_or:
		return "or";
	case op_not:
		return "not";
	default:
		return "";
	}
}

cap::ip::ip(const char* addr, const direction_t& dir,
		const char* mask, const int& len)
	: filter_with_direction(dir)
	, address_(addr)
	, mask_(mask)
	, length_(len)
{
}

std::string cap::ip::parse(void) const
{
	std::string dir = parse_direction();
	std::string addr = address_;
	std::string mask = mask_;
	int len = length_;

	convert_to_ip_with_mask(addr, mask);
	convert_to_ip_with_length(addr, len);

	std::string result = "(ip and " + dir + " net " + addr;
	if (!mask.empty())
		result += " mask " + mask;
	else if (len > 0)
	{
		std::ostringstream stream;
		stream << len;
		result += "/" + stream.str();
	}
	return result + ")";
}

std::shared_ptr<cap::filter> cap::ip::of(const char* addr,
		const direction_t& dir)
{
	return std::make_shared<ip>(addr, dir, "", 0);
}

std::shared_ptr<cap::filter> cap::ip::of(const char* addr,
		const direction_t& dir, const char* mask)
{
	return std::make_shared<ip>(addr, dir, mask, 0);
}

std::shared_ptr<cap::filter> cap::ip::of(const char* addr,
		const direction_t& dir, const int& len)
{
	return std::make_shared<ip>(addr, dir, "", len);
}

void cap::ip::convert_to_ip_with_mask(std::string& addr, std::string& mask) const
{
	if (mask.empty())
		return;

	ipv4_address ipaddr(address_.c_str());
	ipv4_address ipmask(mask_.c_str());
	if (!ipaddr.is_valid() || !ipmask.is_valid())
		mask = "";
	else
	{
		std::uint32_t addr_after_mask = ipaddr.to_int() & ipmask.to_int();
		addr = ipv4_address(addr_after_mask).to_string();
	}
}

void cap::ip::convert_to_ip_with_length(std::string& addr, int& len) const
{
	if (len == 0)
		return;

	std::shared_ptr<ip_address> ipaddr = ip_address::of(addr.c_str());
	if (ipaddr->get_type() == type_ipv4)
	{
		ipv4_address* ip4addr = static_cast<ipv4_address*>(ipaddr.get());
		std::uint32_t addr_as_int = ip4addr->to_int();
		uint32_t mask = ((uint32_t)-1) >> ((sizeof(uint32_t) * 8) - len);
		addr_as_int &= mask;
		addr = ipv4_address(addr_as_int).to_string();
	}
	else if (ipaddr->get_type() == type_ipv6)
	{
		ipv6_address* ip6addr = static_cast<ipv6_address*>(ipaddr.get());
		std::uint64_t addr_low = ip6addr->to_int_low();
		std::uint64_t addr_high = ip6addr->to_int_high();
		if (len > static_cast<int>(sizeof(std::uint64_t) * 8))
		{
			addr_low = 0;
			addr_high &= (-1LL << (len - sizeof(std::uint64_t)));
		}
		else
			addr_low &= (-1LL << len);
		addr = ipv6_address(addr_high, addr_low).to_string();
	}
	else
		len = 0;
}

cap::port::port(const std::uint16_t& port, const direction_t& dir)
	: filter_with_direction(dir)
	, port_(port)
{
}

std::string cap::port::parse(void) const
{
	std::string dir = parse_direction();
	std::ostringstream stream;
	stream << static_cast<int>(port_);
	return "(" + dir + " port " + stream.str() + ")";
}

std::shared_ptr<cap::filter> cap::port::of(const std::uint16_t& port,
	const direction_t& dir)
{
	return std::make_shared<cap::port>(port, dir);
}

cap::port_range::port_range(const std::uint16_t& from,
		const std::uint16_t& to, const direction_t& dir)
	: filter_with_direction(dir)
	, from_(from)
	, to_(to)
{
}

std::shared_ptr<cap::filter> cap::port_range::of(const std::uint16_t& from,
	const std::uint16_t& to, const direction_t& dir)
{
	return std::make_shared<port_range>(from, to, dir);
}

std::string cap::port_range::parse(void) const
{
	std::string dir = parse_direction();
	std::ostringstream from;
	from << static_cast<int>(from_);
	std::ostringstream to;
	to << static_cast<int>(to_);
	return "(" + dir + " portrange " + from.str() + "-" + to.str() + ")";
}

cap::mac::mac(const char* addr, const direction_t& dir)
	: filter_with_direction(dir)
	, address_(addr)
{
}

std::shared_ptr<cap::filter> cap::mac::of(const char* addr,
	const direction_t& dir)
{
	return std::make_shared<mac>(addr, dir);
}

std::string cap::mac::parse(void) const
{
	if (get_direction() == dir_src_or_dst)
		return "(ether host " + address_.to_string() + ")";
	std::string dir = parse_direction();
	return "(ether " + dir + " " + address_.to_string() + ")";
}

cap::ether::ether(const std::uint16_t& type)
	: type_(type)
{
}

std::shared_ptr<cap::filter> cap::ether::of(const std::uint16_t& type)
{
	return std::make_shared<ether>(type);
}

std::string cap::ether::parse(void) const
{
	std::ostringstream stream;
	stream << "0x" << std::hex << type_;
	return "(ether proto " + stream.str() + ")";
}

cap::proto::proto(const protocol_type_t& proto)
	: proto_(proto)
{
}

std::shared_ptr<cap::filter> cap::proto::of(const protocol_type_t& proto)
{
	return std::make_shared<cap::proto>(proto);
}

std::string cap::proto::parse(void) const
{
	switch (proto_)
	{
	case proto_ethernet:
		return "ether";
	case proto_ipv4:
		return "ip";
	case proto_ipv6:
		return "ip6";
	case proto_tcp:
		return "tcp";
	case proto_udp:
		return "udp";
	case proto_icmp:
		return "icmp";
	case proto_vlan:
		return "vlan";
	case proto_arp:
		return "arp";
	default:
		return "";
	}

}

cap::arp::arp(const arp_opcode_t& opcode)
	: opcode_(opcode)
{
}

std::shared_ptr<cap::filter> cap::arp::of(const arp_opcode_t& opcode)
{
	return std::make_shared<arp>(opcode);
}

std::string cap::arp::parse(void) const
{
	std::ostringstream stream;
	stream << opcode_;
	return "(arp[7] = " + stream.str() + ")";
}

cap::vlan::vlan(const std::uint16_t& id)
	: id_(id)
{
}

std::shared_ptr<cap::filter> cap::vlan::of(const uint16_t& id)
{
	return std::make_shared<vlan>(id);
}

std::string cap::vlan::parse(void) const
{
	std::ostringstream stream;
	stream << id_;
	return "(vlan " + stream.str() + ")";
}

cap::tcp::tcp(const int& mask, const bool& match_all)
	: flags_mask_(mask)
	, match_all_(match_all)
{
}

std::shared_ptr<cap::filter> cap::tcp::of(const int& mask,
	const bool& match_all)
{
	return std::make_shared<tcp>(mask, match_all);
}

std::string cap::tcp::parse(void) const
{
	if (flags_mask_ == 0)
		return "";
	std::string result = "(tcp[tcpflags] & (";
	if ((flags_mask_ & tcp_fin) != 0)
		result += "tcp-fin|";
	if ((flags_mask_ & tcp_syn) != 0)
		result += "tcp-syn|";
	if ((flags_mask_ & tcp_rst) != 0)
		result += "tcp-rst|";
	if ((flags_mask_ & tcp_push) != 0)
		result += "tcp-push|";
	if ((flags_mask_ & tcp_ack) != 0)
		result += "tcp-ack|";
	if ((flags_mask_ & tcp_urg) != 0)
		result += "tcp-urg|";
	result = result.substr(0, result.size() - 1);
	result += ")";
	if (match_all_)
	{
		std::ostringstream stream;
		stream << static_cast<int>(flags_mask_);
		result += " = " + stream.str();
	}
	else
		result += " != 0";
	return result + ")";
}

cap::tcp_windows_size::tcp_windows_size(const std::uint16_t& size,
		const operator_t& oper)
	: filter_with_operator(oper)
	, size_(size)
{
}

std::shared_ptr<cap::filter> cap::tcp_windows_size::of(
	const std::uint16_t& size, const operator_t& oper)
{
	return std::make_shared<tcp_windows_size>(size, oper);
}

std::string cap::tcp_windows_size::parse(void) const
{
	std::string op = parse_operator();
	std::ostringstream stream;
	stream << size_;
	return "(tcp[14:2] " + op + " " + stream.str() + ")";
}

cap::udp_length::udp_length(const std::uint16_t& length,
		const operator_t& oper)
	: filter_with_operator(oper)
	, length_(length)
{
}

std::shared_ptr<cap::filter> cap::udp_length::of(const std::uint16_t& length,
	const operator_t& oper)
{
	return std::make_shared<udp_length>(length, oper);
}

std::string cap::udp_length::parse(void) const
{
	std::string op = parse_operator();
	std::ostringstream stream;
	stream << length_;
	return "(udp[4:2] " + op + " " + stream.str() + ")";
}

cap::unary::unary(const operator_t& oper,
		const std::shared_ptr<cap::filter>& filter)
	: filter_with_operator(oper)
	, filter_(filter)
{
}

std::shared_ptr<cap::filter> cap::unary::of(const operator_t& oper,
	const std::shared_ptr<cap::filter>& filter)
{
	return std::make_shared<unary>(oper, filter);
}

std::string cap::unary::parse(void) const
{
	std::string op = parse_operator();
	return "(" + op + " " + filter_->parse() + ")";
}

cap::binary::binary(const operator_t& oper,
		const std::shared_ptr<cap::filter>& left,
		const std::shared_ptr<cap::filter>& right)
	: filter_with_operator(oper)
	, lfilter_(left)
	, rfilter_(right)
{
}

std::shared_ptr<cap::filter> cap::binary::of(const operator_t& oper,
	const std::shared_ptr<cap::filter>& left,
	const std::shared_ptr<cap::filter>& right)
{
	return std::make_shared<binary>(oper, left, right);
}

std::string cap::binary::parse(void) const
{
	std::string op = parse_operator();
	return "(" + lfilter_->parse() + " " + op + " " + rfilter_->parse() + ")";
}

cap::filter_builder::filter_builder(const std::shared_ptr<cap::filter>& filtr)
	: filter_(filtr)
{
}

cap::filter_builder& cap::filter_builder::op(
	const operator_t& oper, const std::shared_ptr<cap::filter>& right)
{
	if (right != nullptr)
		filter_ = (filter_ == nullptr) ?
			right : binary::of(oper, filter_, right);
	return *this;

}

cap::filter_builder& cap::filter_builder::op(
	const std::shared_ptr<cap::filter>& left, const operator_t& oper)
{
	if (left != nullptr)
		filter_ = (filter_ == nullptr) ?
			left : binary::of(oper, left, filter_);
	return *this;
}

cap::filter_builder& cap::filter_builder::op(const operator_t& oper)
{
	if (filter_ != nullptr)
		filter_ = unary::of(oper, filter_);
	return *this;
}

cap::filter_builder& cap::filter_builder::op_and(
	const std::shared_ptr<cap::filter>& right)
{
	return op(cap::op_and, right);
}

cap::filter_builder& cap::filter_builder::op_and_not(
	const std::shared_ptr<cap::filter>& right)
{
	return op_and(unary::of(cap::op_not, right));
}

cap::filter_builder& cap::filter_builder::op_and_any_of(
	const std::initializer_list<std::shared_ptr<cap::filter>>& args)
{
	std::shared_ptr<filter> rv = nullptr;
	for (const auto& a : args)
		if (a != nullptr)
			rv = rv == nullptr ? a : binary::of(cap::op_or, rv, a);
	if (rv != nullptr)
		return op_and(rv);
	return *this;
}

cap::filter_builder& cap::filter_builder::op_or(
	const std::shared_ptr<cap::filter>& right)
{
	return op(cap::op_or, right);
}

cap::filter_builder& cap::filter_builder::op_or_not(
	const std::shared_ptr<filter>& right)
{
	return op_or(unary::of(cap::op_not, right));
}

cap::filter_builder& cap::filter_builder::op_or_all_of(
	const std::initializer_list<std::shared_ptr<cap::filter>>& args)
{
	std::shared_ptr<filter> rv = nullptr;
	for (const auto& a : args)
		if (a != nullptr)
			rv = rv == nullptr ? a : binary::of(cap::op_and, rv, a);
	if (rv != nullptr)
		return op_or(rv);
	return *this;
}

cap::filter_builder& cap::filter_builder::op_not(void)
{
	return op(cap::op_not);
}

std::shared_ptr<cap::filter> cap::filter_builder::build(void) const
{
	return filter_;
}
