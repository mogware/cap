#ifndef __CAP_FILTER__
#define __CAP_FILTER__

#include "cap.mac_address.h"
#include "cap.noncopyable.h"

#include <string>
#include <cstdint>
#include <memory>
#include <initializer_list>

namespace cap
{
	typedef enum { dir_src, dir_dst, dir_src_or_dst } direction_t;
	typedef enum {
		op_eq, op_ne, op_gt, op_ge, op_lt, op_le, op_and, op_or, op_not
	} operator_t;
	typedef enum
	{
		proto_unknown = 0x00,
		proto_ethernet = 0x01,
		proto_ipv4 = 0x02,
		proto_ipv6 = 0x04,
		proto_ip = 0x06,
		proto_tcp = 0x08,
		proto_udp = 0x010,
		proto_arp = 0x80,
		proto_icmp = 0x200,
		proto_vlan = 0x100
	} protocol_type_t;
	
	typedef enum { arp_request = 0x0001, arp_reply = 0x0002 } arp_opcode_t;
	typedef enum { tcp_fin = 1, tcp_syn = 2, tcp_rst = 4, tcp_push = 8,
		tcp_ack = 16, tcp_urg = 32 } tcp_flags_t;

	struct filter
	{
		virtual std::string parse() const = 0;
		virtual ~filter(void);
	};

	class filter_with_direction : public filter
	{
		direction_t dir_;
	protected:
		filter_with_direction(const direction_t& dir);
	protected:
		std::string parse_direction(void) const;
	protected:
		direction_t get_direction(void) const;
	};

	class filter_with_operator : public filter
	{
		operator_t oper_;
	protected:
		filter_with_operator(const operator_t& oper);
	protected:
		std::string parse_operator(void) const;
	};

	class ip : public filter_with_direction, private noncopyable
	{
		std::string address_;
		std::string mask_;
		int length_;
	public:
		ip(const char* addr, const direction_t& dir,
			const char* mask, const int& len);
	public:
		std::string parse(void) const;
	public:
		static std::shared_ptr<filter> of(const char* addr,
			const direction_t& dir);
		static std::shared_ptr<filter> of(const char* addr,
			const direction_t& dir, const char* mask);
		static std::shared_ptr<filter> of(const char* addr,
			const direction_t& dir, const int& len);
	private:
		void convert_to_ip_with_mask(std::string& addr, std::string& mask) const;
		void convert_to_ip_with_length(std::string& addr, int& len) const;
	};

	class port : public filter_with_direction, private noncopyable
	{
		std::uint16_t port_;
	public:
		port(const std::uint16_t& port, const direction_t& dir);
	public:
		static std::shared_ptr<filter> of(const std::uint16_t& port,
			const direction_t& dir);
	public:
		std::string parse(void) const;
	};

	class port_range : public filter_with_direction, private noncopyable
	{
		std::uint16_t from_;
		std::uint16_t to_;
	public:
		port_range(const std::uint16_t& from,
			const std::uint16_t& to, const direction_t& dir);
	public:
		static std::shared_ptr<filter> of(const std::uint16_t& from,
			const std::uint16_t& to, const direction_t& dir);
	public:
		std::string parse(void) const;
	};

	class mac : public filter_with_direction, private noncopyable
	{
		mac_address address_;
	public:
		mac(const char* addr, const direction_t& dir);
	public:
		static std::shared_ptr<filter> of(const char* addr,
			const direction_t& dir);
	public:
		std::string parse(void) const;
	};

	class ether : public filter, private noncopyable
	{
		std::uint16_t type_;
	public:
		ether(const std::uint16_t& type);
	public:
		static std::shared_ptr<filter> of(const std::uint16_t& type);
	public:
		std::string parse(void) const;
	};

	class proto : public filter, private noncopyable
	{
		protocol_type_t proto_;
	public:
		proto(const protocol_type_t& proto);
	public:
		static std::shared_ptr<filter> of(const protocol_type_t& proto);
	public:
		std::string parse(void) const;
	};

	class arp : public filter, private noncopyable
	{
		arp_opcode_t opcode_;
	public:
		arp(const arp_opcode_t& opcode);
	public:
		static std::shared_ptr<filter> of(const arp_opcode_t& opcode);
	public:
		std::string parse(void) const;
	};

	class vlan : public filter, private noncopyable
	{
		std::uint16_t id_;
	public:
		vlan(const uint16_t& id);
	public:
		static std::shared_ptr<filter> of(const uint16_t& id);
	public:
		std::string parse(void) const;
	};

	class tcp : public filter, private noncopyable
	{
		int flags_mask_;
		bool match_all_;
	public:
		tcp(const int& mask, const bool& match_all = true);
	public:
		static std::shared_ptr<filter> of(const int& mask,
			const bool& match_all = true);
	public:
		std::string parse(void) const;
	};

	class tcp_windows_size : public filter_with_operator, private noncopyable
	{
		std::uint16_t size_;
	public:
		tcp_windows_size(const std::uint16_t& size, const operator_t& oper);
	public:
		static std::shared_ptr<filter> of(const std::uint16_t& size,
			const operator_t& oper);
	public:
		std::string parse(void) const;
	};

	class udp_length : public filter_with_operator, private noncopyable
	{
		std::uint16_t length_;
	public:
		udp_length(const std::uint16_t& length, const operator_t& oper);
	public:
		static std::shared_ptr<filter> of(const std::uint16_t& length,
			const operator_t& oper);
	public:
		std::string parse(void) const;
	};

	class unary : public filter_with_operator, private noncopyable
	{
		std::shared_ptr<filter> filter_;
	public:
		unary(const operator_t& oper,
			const std::shared_ptr<filter>& filter);
	public:
		static std::shared_ptr<filter> of(const operator_t& oper,
			const std::shared_ptr<filter>& filter);
	public:
		std::string parse(void) const;
	};

	class binary : public filter_with_operator, private noncopyable
	{
		std::shared_ptr<filter> lfilter_;
		std::shared_ptr<filter> rfilter_;
	public:
		binary(const operator_t& oper,
			const std::shared_ptr<filter>& left,
			const std::shared_ptr<filter>& right);
	public:
		static std::shared_ptr<filter> of(const operator_t& oper,
			const std::shared_ptr<filter>& left,
			const std::shared_ptr<filter>& right);
	public:
		std::string parse(void) const;
	};

	class filter_builder : private noncopyable
	{
		std::shared_ptr<filter> filter_;
	public:
		filter_builder(const std::shared_ptr<filter>& filtr);
	public:
		filter_builder& op(const operator_t& oper,
			const std::shared_ptr<filter>& right);
		filter_builder& op(const std::shared_ptr<filter>& left,
			const operator_t& oper);
		filter_builder& op(const operator_t& oper);
	public:
		filter_builder& op_and(const std::shared_ptr<filter>& right);
		filter_builder& op_and_not(const std::shared_ptr<filter>& right);
		filter_builder& op_and_any_of(
			const std::initializer_list<std::shared_ptr<filter>>& args);
	public:
		filter_builder& op_or(const std::shared_ptr<filter>& right);
		filter_builder& op_or_not(const std::shared_ptr<filter>& right);
		filter_builder& op_or_all_of(
			const std::initializer_list<std::shared_ptr<filter>>& args);
	public:
		filter_builder& op_not(void);
	public:
		std::shared_ptr<filter> build(void) const;
	};
}

#endif




